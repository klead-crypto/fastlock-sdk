"use client";

/**
 * AES-GCM and ECDH in the browser, for the one thing in this app that touches a server.
 *
 * A room's audio, video and messages are never encrypted here — they travel over WebRTC,
 * which is DTLS-encrypted end to end between the two browsers and never passes through us.
 * There is nothing for this file to do on that path.
 *
 * The short link is the exception. A five-character code has to be redeemable by somebody
 * who has not connected yet, so the invitation it stands for has to be written down
 * somewhere both peers can reach, and that somewhere is our database.
 *
 * Which raises the obvious question: if the link is `otc.fastlock.pro/s/x7Y2q` and nothing
 * follows it, where is the key? A URL fragment would answer it — browsers never send the
 * part after `#` — but a fragment is exactly what makes a short link long again, and the
 * point of paying for one is a link you can read out whole.
 *
 * So there is no key in the link. The two browsers make one between themselves, through
 * the code, using ECDH: each generates an ephemeral P-256 pair and posts only its *public*
 * half, and each combines its own private half with the other's public one. Both arrive at
 * the same 256-bit secret. The server carried both messages and can derive nothing from
 * them — a public key is public, and the private halves never leave the two tabs.
 *
 * Be exact about the limit, because it is a real one. This is unauthenticated Diffie-
 * Hellman, so a server that actively substituted its own public key for each side could sit
 * in the middle and read the invitation. It could not do anything with it: the invite
 * carries a wallet signature over the host's DTLS fingerprint, checked in the other browser
 * against an address the opener wrote down by hand, so a middle cannot impersonate either
 * party or enter the room. What it protects absolutely is the passive case — a database
 * dump, a backup, a subpoena, a curious operator reading rows — where there is now nothing
 * to read at all.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function generateKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

export async function exportKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return toBase64Url(new Uint8Array(raw));
}

export async function importKey(value: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    fromBase64Url(value) as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

// ── ECDH: the key the server never sees ──────────────────────────────────────

/** P-256, because it is the curve `crypto.subtle` supports everywhere without a library. */
const CURVE = { name: "ECDH", namedCurve: "P-256" } as const;

/**
 * One side's ephemeral pair, generated fresh per room and thrown away with the tab.
 *
 * Non-extractable on purpose: `crypto.subtle` will hand out the public half and refuse the
 * private one, which means there is no code path in this app — or in anything injected into
 * it — that can read the private key out of memory and post it somewhere.
 */
export interface Ephemeral {
  /** Kept. Never leaves the tab, and cannot be exported. */
  privateKey: CryptoKey;
  /** Published under the code, in the clear. A public key is public. */
  publicKey: string;
}

export async function generateEphemeral(): Promise<Ephemeral> {
  const pair = await crypto.subtle.generateKey(CURVE, false, ["deriveKey"]);
  const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: toBase64Url(new Uint8Array(raw)) };
}

/**
 * Combines our private half with their public half to reach the shared AES key.
 *
 * Both sides run this with the halves swapped and land on the same 256 bits — that is the
 * whole of Diffie-Hellman. The result is derived straight into an AES-GCM key rather than
 * exported as bytes, so the secret itself never exists as a JavaScript value that could be
 * logged, serialised or stepped over in a debugger.
 *
 * Throws on a public key that is not a point on the curve, which is what a substituted or
 * corrupted value looks like. The caller reports that rather than proceeding.
 */
export async function deriveShared(
  ours: CryptoKey,
  theirs: string,
): Promise<CryptoKey> {
  const publicKey = await crypto.subtle.importKey(
    "raw",
    fromBase64Url(theirs) as BufferSource,
    CURVE,
    false,
    [],
  );

  return crypto.subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    ours,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Seals a string: a fresh 96-bit IV, then AES-GCM, then one base64url blob.
 *
 * The IV is prefixed rather than stored beside the ciphertext so the result is a single
 * opaque string — something that can be put in a database column, a URL or a JSON field
 * without anybody downstream needing to know it has parts.
 */
export async function seal(key: CryptoKey, text: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(text),
  );
  const out = new Uint8Array(iv.length + cipher.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(cipher), iv.length);
  return toBase64Url(out);
}

/**
 * Opens a sealed string, or throws.
 *
 * GCM authenticates as well as encrypts, so this fails on a wrong key and on a tampered
 * blob alike — which is what lets a caller treat "will not open" as "was not written by
 * someone holding the key" rather than having to trust the sender of the bytes.
 */
export async function unseal(key: CryptoKey, value: string): Promise<string> {
  const bytes = fromBase64Url(value);
  const iv = bytes.slice(0, 12);
  const cipher = bytes.slice(12);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    cipher as BufferSource,
  );
  return decoder.decode(plain);
}
