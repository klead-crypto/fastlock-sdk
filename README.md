# fastlock-sdk

The engine behind [FastLock](https://fastlock.pro), pulled out of the product and published on its own.

This is the part that does the work: WebRTC file transfer, encrypted calls, the crypto helpers, the IndexedDB chunk store. No UI, no framework, no dependencies. It runs in a browser and talks to exactly one other browser.

- **Zero dependencies.** Everything is Web Crypto, WebRTC and IndexedDB — all of it standard in the browser.
- **No server holds your data.** Bytes go directly between the two peers over a DTLS-encrypted data channel. Nothing is uploaded anywhere.
- **The server seams are yours.** The two places FastLock needs a backend — signalling and TURN — are parameters, not hardcoded URLs. Point them anywhere or leave them out.
- **TypeScript, strict.** Compiled with `strict` and `noUncheckedIndexedAccess`.

## Install

Not on npm yet. For now, either point at the repository:

```
npm install github:dimazaytsev82-crypto/fastlock-sdk
```

or copy the `src/` directory into your project — it is eight files and imports nothing but the browser.

## What is in it

| Module | What it does |
| --- | --- |
| `transfer` | Send and receive a file peer-to-peer, with backpressure and disk-backed reassembly |
| `call` | Audio, video and screen share between two peers, plus a chat channel, with manual signalling |
| `crypto` | AES-GCM sealing, ECDH key agreement, base64url |
| `handshake` | Compact, compressed invite/reply codes for out-of-band signalling |
| `ice` | STUN defaults and an optional TURN credential fetch |
| `idb` | An IndexedDB chunk store, so a large file never sits in memory |
| `ids` | Short URL-safe random identifiers |

## File transfer

The sender streams a `Blob`; the receiver writes each chunk to IndexedDB and hands you back a `Blob` at the end. The sender stops at a 1 MB channel buffer and waits for it to drain, which is what keeps a multi-gigabyte file from killing the tab.

```ts
import { startSender, runReceiver, saveBlob } from "fastlock-sdk";

// Sender
const handle = startSender({
  transferId,
  ownerToken,
  blob: file,
  onProgress: (p) => console.log(p.phase, p.bytes, "/", p.total, p.rate + " B/s"),
});
await handle.finished; // resolves once the receiver confirms every byte landed
// handle.cancel() tears it down early

// Receiver
const blob = await runReceiver({
  transferId,
  token,
  sizeBytes,
  mimeType,
  onProgress: (p) => console.log(p.phase, p.bytes),
});
saveBlob(blob, "photo.zip");
```

### Signalling is pluggable

Two browsers cannot find each other unaided — somebody has to carry four short messages between them before the peer connection exists. That carrier never sees a byte of the file. Implement `SignalTransport` and it can be anything that moves JSON:

```ts
import type { SignalTransport, Envelope } from "fastlock-sdk";

const transport: SignalTransport = {
  async send(message: Envelope) { /* push to your channel */ },
  async receive(): Promise<Envelope[]> { /* everything since the last call */ return []; },
  clear() { /* optional teardown */ },
};

startSender({ transferId, ownerToken, blob, onProgress, transport });
```

Leave `transport` out and you get `HttpSignalTransport`, which polls `POST`/`GET` on `/api/webrtc/signal`. That is one implementation, not the interface.

## Calls

`Call` carries no server at all — not one `fetch` in the file, apart from the optional TURN lookup. The offer and the answer come back to you as text, and a human carries them across whatever conversation the two people already have.

```ts
import { Call } from "fastlock-sdk";

const call = new Call("host", {
  onStatus: (s) => console.log(s),
  onChat: (line) => console.log(line.mine ? "me" : "them", line.body),
  onSafetyNumber: (value) => console.log("compare out loud:", value),
  onRelay: (available) => console.log("relay:", available),
});

const invite = await call.createOffer();   // { sdp, fingerprint } — send this to the other side
await call.acceptAnswer(theirAnswerSdp);   // paste back what they returned

// on the other side
const guest = new Call("guest", handlers);
const reply = await guest.answerOffer(theirOfferSdp);
guest.awaitConnection();
```

Media and chat once connected:

```ts
await call.setMicrophone(true);
await call.setCamera(true);
await call.setScreen(true);
call.sendChat("hello");
call.hangUp();
```

Attach `call.localCam`, `call.localScreen`, `call.remoteCam` and `call.remoteScreen` to `<video>` elements. `call.safetyNumber` is a short digest of both DTLS fingerprints — if it matches on both screens, nobody is in the middle.

Because there is no signalling channel after setup, the design has one honest limit: if the transport dies completely, there is no outside path left to repair it. A dropped room has to be opened again.

## Encryption

WebRTC is encrypted by the standard and cannot be turned off. Media is SRTP keyed by a DTLS handshake performed between the two browsers; chat and file data ride the same DTLS association over SCTP. Nobody in the middle holds those keys — not a signalling server, not a TURN relay.

`crypto` is separate from that, for the things you carry out of band:

```ts
import { generateKey, exportKey, importKey, seal, unseal } from "fastlock-sdk";
import { generateEphemeral, deriveShared } from "fastlock-sdk";

const key = await generateKey();
const token = await seal(key, "some text");   // AES-256-GCM, base64url
const text = await unseal(key, token);

// or agree on a key with the other side, ECDH P-256
const mine = await generateEphemeral();          // mine.publicKey is base64url, safe to publish
const shared = await deriveShared(mine.privateKey, theirPublicKey);
```

Both sides derive the same AES-256-GCM key, and a carrier that moved both public keys can derive nothing from them.

## STUN and TURN

STUN discovers your public address, and for most pairs of home networks that is the whole job. It is not enough between two symmetric NATs — mobile carriers, corporate and campus wifi — where a TURN relay forwarding the packets is the only fix. The relay cannot read them: it moves sealed DTLS records and holds none of the keys. It does see both IP addresses, which is worth saying out loud.

The relay credential is fetched rather than compiled in, because a credential in the bundle is a permanent one published to every visitor. Point it at a route of your own that mints a short-lived one:

```ts
import { iceServers } from "fastlock-sdk";

const { servers, relayed } = await iceServers("/api/turn"); // your route
const stunOnly = await iceServers(null);                    // skip the request entirely
```

Your route should answer `{ urls: string[], username: string, credential: string }`. Anything else is treated as a refusal, and a refusal is not a failure — you still get the STUN list and a direct connection, which is what the great majority of transfers and calls use anyway.

Every entry point takes `turnEndpoint`:

```ts
startSender({ ..., turnEndpoint: "/my/turn" });
runReceiver({ ..., turnEndpoint: null });
new Call("host", handlers, "/my/turn");
```

## Browser support

Needs `RTCPeerConnection`, `crypto.subtle` and `indexedDB`; screen share additionally needs `getDisplayMedia`. Current Chrome, Edge, Firefox and Safari all qualify. `handshake` uses `CompressionStream` where it exists and falls back to an uncompressed code where it does not. It is browser-only — there is no Node build.

## Building

```
npm install
npm run build      # emits dist/ with .d.ts
npm run typecheck
```

## License

MIT. See [LICENSE](LICENSE).
