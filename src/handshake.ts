/**
 * The handshake blobs.
 *
 * Two browsers with no server in common cannot find each other by themselves: WebRTC
 * needs a session description to cross from one to the other, and something has to
 * carry it. This file is that something — not a channel, just a format. The invite and
 * the reply are compressed into text that a human moves between the two tabs through
 * whatever conversation they were already having.
 *
 * That is the whole trick behind the privacy claim. There is no signalling server to
 * log the meeting because there is no signalling server, and the price is one extra
 * message in a chat window that was open anyway.
 *
 * The blobs travel in the URL fragment, after the `#`. Fragments are never transmitted
 * to the origin server — not in the request line, not in a referrer header — so even
 * the machine serving this page never learns them.
 */

/** Bumped if the shape below ever changes, so an old link fails loudly. */
export const HANDSHAKE_VERSION = 1;

/** What the host publishes: an offer, plus proof of who is offering. */
export interface Invite {
  v: number;
  /** The host's own address, recovered independently from `sig`. */
  host: string;
  /** The address this room is locked to. Only this wallet can answer. */
  guest: string;
  /** Random, per room. The guest signs it, which is what stops a replay. */
  nonce: string;
  /** SHA-256 of the host's DTLS certificate, binding the signature to the connection. */
  fp: string;
  /** The host's signature over the statement in `identity.ts`. */
  sig: string;
  /** A complete offer: ICE gathering has finished, so there is nothing to trickle. */
  sdp: string;
  at: number;
}

/** What the guest sends back: an answer, plus proof of who is answering. */
export interface Reply {
  v: number;
  guest: string;
  fp: string;
  sig: string;
  sdp: string;
  at: number;
}

/**
 * An invite is stale once it is this old.
 *
 * Nothing enforces this but the two people involved — there is no server to expire it.
 * The offer usually dies sooner anyway, because it stops meaning anything the moment
 * the host closes the tab holding the connection it describes.
 */
export const INVITE_TTL_MS = 30 * 60 * 1000;

// ── text encoding ────────────────────────────────────────────────────────────

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  // Chunked, because a spread of a few thousand arguments overflows the call stack.
  const step = 0x8000;
  for (let index = 0; index < bytes.length; index += step) {
    binary += String.fromCharCode(...bytes.subarray(index, index + step));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/**
 * Deflate, if the browser has it.
 *
 * An SDP is extremely repetitive — the same candidate lines with different ports — so
 * this reliably cuts it to about a third, which is the difference between a link that
 * survives being pasted into a chat app and one that does not. `CompressionStream` is
 * standard in every browser that can hold a WebRTC call, but the uncompressed path
 * below keeps the format working rather than throwing if it is ever missing.
 */
async function squeeze(
  bytes: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (typeof CompressionStream === "undefined") return null;
  try {
    const stream = new CompressionStream("deflate-raw");
    const writer = stream.writable.getWriter();
    void writer.write(bytes);
    void writer.close();
    return new Uint8Array(await new Response(stream.readable).arrayBuffer());
  } catch {
    return null;
  }
}

async function expand(
  bytes: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const stream = new DecompressionStream("deflate-raw");
  const writer = stream.writable.getWriter();
  void writer.write(bytes);
  void writer.close();
  return new Uint8Array(await new Response(stream.readable).arrayBuffer());
}

// ── the format ───────────────────────────────────────────────────────────────

/** `D` for deflated, `P` for plain. One byte, so the reader never has to guess. */
const DEFLATED = "D";
const PLAIN = "P";

export async function pack(value: Invite | Reply): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const squeezed = await squeeze(bytes);
  return squeezed && squeezed.length < bytes.length
    ? DEFLATED + toBase64Url(squeezed)
    : PLAIN + toBase64Url(bytes);
}

async function unpack(code: string): Promise<unknown> {
  const trimmed = code.trim();
  const marker = trimmed.slice(0, 1);
  const body = fromBase64Url(trimmed.slice(1));

  if (marker === DEFLATED) return JSON.parse(new TextDecoder().decode(await expand(body)));
  if (marker === PLAIN) return JSON.parse(new TextDecoder().decode(body));
  throw new Error("unrecognised");
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * Decodes an invite, or explains why it will not decode.
 *
 * Everything here is shape-checking only. Nothing is trusted until the signature has
 * been verified in `identity.ts` — this just guarantees the fields exist to verify.
 */
export async function readInvite(code: string): Promise<Invite> {
  let value: unknown;
  try {
    value = await unpack(code);
  } catch {
    throw new Error("This invitation is damaged — it was probably cut short in transit.");
  }

  const invite = value as Partial<Invite>;
  if (invite.v !== HANDSHAKE_VERSION) {
    throw new Error("This invitation was made by a different version of FastLock OTC.");
  }
  if (
    !isString(invite.host) ||
    !isString(invite.guest) ||
    !isString(invite.nonce) ||
    !isString(invite.fp) ||
    !isString(invite.sig) ||
    !isString(invite.sdp)
  ) {
    throw new Error("This invitation is incomplete.");
  }

  return {
    v: invite.v,
    host: invite.host,
    guest: invite.guest,
    nonce: invite.nonce,
    fp: invite.fp,
    sig: invite.sig,
    sdp: invite.sdp,
    at: typeof invite.at === "number" ? invite.at : 0,
  };
}

export async function readReply(code: string): Promise<Reply> {
  let value: unknown;
  try {
    value = await unpack(code);
  } catch {
    throw new Error("That reply code is damaged — copy the whole thing and try again.");
  }

  const reply = value as Partial<Reply>;
  if (reply.v !== HANDSHAKE_VERSION) {
    throw new Error("That reply came from a different version of FastLock OTC.");
  }
  if (
    !isString(reply.guest) ||
    !isString(reply.fp) ||
    !isString(reply.sig) ||
    !isString(reply.sdp)
  ) {
    throw new Error("That reply code is incomplete.");
  }

  return {
    v: reply.v,
    guest: reply.guest,
    fp: reply.fp,
    sig: reply.sig,
    sdp: reply.sdp,
    at: typeof reply.at === "number" ? reply.at : 0,
  };
}
