const ALPHABET = "abcdefghijkmnopqrstuvwxyz23456789";

/** URL-safe, unambiguous, CSPRNG-backed identifier. 22 chars ≈ 110 bits. */
export function newId(length = 22): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const byte of bytes) out += ALPHABET[byte % ALPHABET.length];
  return out;
}

export function newNonce(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
