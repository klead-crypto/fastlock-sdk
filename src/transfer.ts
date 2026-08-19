/**
 * The transfer itself: two browsers, one encrypted channel, no server in the middle.
 *
 * A signalling server sees the handshake — the offer, the answer, the ICE candidates — and
 * nothing else. The bytes go directly from one machine to the other over a DTLS-encrypted
 * SCTP data channel and are never uploaded anywhere. There is no copy on the server side to
 * protect, to leak, or to delete afterwards.
 *
 * Two problems dominate the design, and both are about not falling over on large files. The
 * sender must not outrun the channel — writing a 5 GB file into it as fast as JavaScript can
 * read is how a tab dies — so it stops at a 1 MB buffer and waits to be asked for more. The
 * receiver must not accumulate the file in memory — on iOS that is fatal well before a
 * gigabyte — so every chunk goes to IndexedDB as it lands.
 */

import { DEFAULT_TURN_ENDPOINT, iceServers } from "./ice.js";
import { ChunkStore } from "./idb.js";

/** SCTP is interoperable at 16 KB; larger messages are a coin flip across browsers. */
export const CHUNK_BYTES = 16 * 1024;

/** Stop filling the channel above this, and resume when it drains. */
export const BUFFER_HIGH = 1024 * 1024;
export const BUFFER_LOW = 256 * 1024;

export type Phase =
  | "waiting"
  | "connecting"
  | "transferring"
  | "finishing"
  | "done"
  | "error";

export interface Progress {
  phase: Phase;
  bytes: number;
  total: number;
  /** Bytes per second, smoothed. */
  rate: number;
  message?: string;
}

export type Kind = "hello" | "offer" | "answer" | "candidate";

export interface Envelope {
  kind: Kind;
  payload: Record<string, unknown>;
}

/**
 * The one thing this library cannot do for you.
 *
 * Two browsers cannot find each other unaided: somebody has to carry four short messages
 * between them before the peer connection exists. That carrier is the only server in a
 * transfer, it never sees a byte of the file, and it can be anything that moves JSON — a
 * database table polled over HTTP, a WebSocket, a message queue, or a human pasting text
 * into a chat window. `HttpSignalTransport` below is one implementation, not the interface.
 */
export interface SignalTransport {
  /** Hand a message to the other peer. */
  send(message: Envelope): Promise<void>;
  /** Everything addressed to this peer since the last call. Empty array if nothing. */
  receive(): Promise<Envelope[]>;
  /** Best-effort teardown once the transfer is over. */
  clear?(): void;
}

/**
 * Why the connection failed, in terms of what can actually be done about it.
 *
 * "Your networks block peer-to-peer" is not useful to either person when the real answer
 * is that this transfer had no relay to fall back on — and the fix for that depends on
 * which reason it had none. A VIP whose relay stayed silent should try again; everybody
 * else is looking at a tier boundary, and saying so is the difference between a bug
 * report and a shrug.
 */
function connectionFailure(relayed: boolean): Error {
  return new Error(
    relayed
      ? "Could not open a direct connection, and the relay did not answer either. Try again, or try a different network."
      : "Could not open a direct connection between these two networks. Mobile data and office Wi-Fi usually need a relay, which is part of VIP — on the same Wi-Fi this works without one.",
  );
}

export const DEFAULT_SIGNAL_ENDPOINT = "/api/webrtc/signal";

/**
 * A transport over one HTTP route: POST to send, GET to drain, DELETE to tear down.
 *
 * Deliberately dull. Polling beats a socket here because the whole exchange is four
 * messages long and then finished — a connection held open for the life of a 40 GB
 * transfer, to carry nothing after the first second, is a cost with no return.
 */
export class HttpSignalTransport implements SignalTransport {
  constructor(
    private readonly transferId: string,
    private readonly token: string | null,
    private readonly endpoint: string = DEFAULT_SIGNAL_ENDPOINT,
  ) {}

  private query(): string {
    const query = new URLSearchParams({ transferId: this.transferId });
    if (this.token) query.set("token", this.token);
    return query.toString();
  }

  async send(message: Envelope): Promise<void> {
    const response = await fetch(this.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        transferId: this.transferId,
        token: this.token,
        kind: message.kind,
        payload: message.payload,
      }),
    });
    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as { error?: string } | null;
      throw new Error(body?.error ?? "Signalling failed");
    }
  }

  async receive(): Promise<Envelope[]> {
    const response = await fetch(`${this.endpoint}?${this.query()}`);
    if (!response.ok) return [];
    const body = (await response.json()) as { messages?: Envelope[] };
    return body.messages ?? [];
  }

  clear(): void {
    void fetch(`${this.endpoint}?${this.query()}`, { method: "DELETE" }).catch(
      () => undefined,
    );
  }
}

/** Drives a transport: send by kind, and keep draining the inbox until stopped. */
class Signaller {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = false;

  constructor(private readonly transport: SignalTransport) {}

  send(kind: Kind, payload: Record<string, unknown>): Promise<void> {
    return this.transport.send({ kind, payload });
  }

  poll(onMessage: (message: Envelope) => void, intervalMs = 1000): void {
    const tick = async () => {
      if (this.stopped) return;
      try {
        for (const message of await this.transport.receive()) onMessage(message);
      } catch {
        // A dropped poll is not fatal; the next one picks the messages up.
      }
      if (!this.stopped) this.timer = setTimeout(tick, intervalMs);
    };
    void tick();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  clear(): void {
    this.transport.clear?.();
  }
}

/** Smooths the byte rate so the UI reads as a speed, not a stutter. */
class Rate {
  private last = Date.now();
  private lastBytes = 0;
  private value = 0;

  update(bytes: number): number {
    const now = Date.now();
    const elapsed = now - this.last;
    if (elapsed < 400) return this.value;
    const instant = ((bytes - this.lastBytes) * 1000) / elapsed;
    this.value = this.value === 0 ? instant : this.value * 0.7 + instant * 0.3;
    this.last = now;
    this.lastBytes = bytes;
    return this.value;
  }
}

function waitFor(channel: RTCDataChannel, event: "open"): Promise<void> {
  return new Promise((resolve, reject) => {
    if (channel.readyState === "open") {
      resolve();
      return;
    }
    channel.addEventListener(event, () => resolve(), { once: true });
    channel.addEventListener("error", () => reject(new Error("Channel failed")), {
      once: true,
    });
    channel.addEventListener(
      "close",
      () => reject(new Error("Channel closed before it opened")),
      { once: true },
    );
  });
}

/**
 * Reads one slice of the file.
 *
 * FileReader rather than Blob.arrayBuffer(): it is the path that has worked on every
 * iOS Safari version this has to run on, and the file is being read one 16 KB slice at
 * a time either way.
 */
function readSlice(blob: Blob): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error ?? new Error("Could not read the file"));
    reader.readAsArrayBuffer(blob);
  });
}

export interface SenderHandle {
  /** Resolves when the receiver confirms every byte is on their disk. */
  finished: Promise<void>;
  cancel(): void;
}

export interface SendOptions {
  transferId: string;
  /** The one-time credential handed back at creation; this tab's proof it is the sender. */
  ownerToken: string;
  blob: Blob;
  onProgress(progress: Progress): void;
  /** Defaults to `HttpSignalTransport` against `DEFAULT_SIGNAL_ENDPOINT`. */
  transport?: SignalTransport;
  /** Where to ask for a TURN credential. `null` goes STUN-only. */
  turnEndpoint?: string | null;
}

/**
 * Holds a session open, waits for the recipient, then feeds them the file.
 *
 * Returns as soon as the session is listening — the returned promise resolves when the
 * receiver has acknowledged the last chunk.
 */
export function startSender(options: SendOptions): SenderHandle {
  const { transferId, ownerToken, blob, onProgress } = options;
  const turnEndpoint =
    options.turnEndpoint === undefined ? DEFAULT_TURN_ENDPOINT : options.turnEndpoint;
  const signaller = new Signaller(
    options.transport ?? new HttpSignalTransport(transferId, ownerToken),
  );
  const rate = new Rate();

  let pc: RTCPeerConnection | null = null;
  let channel: RTCDataChannel | null = null;
  let cancelled = false;
  let sending = false;

  const pendingCandidates: RTCIceCandidateInit[] = [];
  let remoteSet = false;

  const cleanup = () => {
    signaller.stop();
    channel?.close();
    pc?.close();
    channel = null;
    pc = null;
  };

  const finished = new Promise<void>((resolve, reject) => {
    const fail = (error: Error) => {
      onProgress({ phase: "error", bytes: 0, total: blob.size, rate: 0, message: error.message });
      cleanup();
      reject(error);
    };

    const pump = async () => {
      if (!channel) return;
      const active = channel;
      let sent = 0;
      let index = 0;

      onProgress({ phase: "transferring", bytes: 0, total: blob.size, rate: 0 });

      while (sent < blob.size) {
        if (cancelled) throw new Error("Cancelled");
        if (active.readyState !== "open") throw new Error("The connection dropped");

        // Backpressure. Above the high-water mark we stop reading the file entirely and
        // wait to be told the channel has drained — this is what keeps a multi-gigabyte
        // send from ballooning the tab's memory and being killed.
        if (active.bufferedAmount > BUFFER_HIGH) {
          await new Promise<void>((done) => {
            active.bufferedAmountLowThreshold = BUFFER_LOW;
            active.addEventListener("bufferedamountlow", () => done(), { once: true });
          });
          continue;
        }

        const end = Math.min(sent + CHUNK_BYTES, blob.size);
        const chunk = await readSlice(blob.slice(sent, end));
        active.send(chunk);
        sent = end;
        index += 1;

        if (index % 16 === 0 || sent === blob.size) {
          onProgress({
            phase: "transferring",
            bytes: sent,
            total: blob.size,
            rate: rate.update(sent),
          });
        }
      }

      active.send(JSON.stringify({ type: "done", bytes: blob.size }));
      onProgress({ phase: "finishing", bytes: blob.size, total: blob.size, rate: 0 });
    };

    const onHello = async () => {
      if (sending) return;
      sending = true;

      onProgress({ phase: "connecting", bytes: 0, total: blob.size, rate: 0 });

      // Asked for before construction, not after: the ICE servers are constructor
      // arguments, and once candidates are being gathered it is too late to add one.
      const { servers, relayed } = await iceServers(turnEndpoint);

      const connection = new RTCPeerConnection({ iceServers: servers });
      pc = connection;

      const data = connection.createDataChannel("fl", { ordered: true });
      data.binaryType = "arraybuffer";
      channel = data;

      data.addEventListener("message", (event) => {
        if (typeof event.data !== "string") return;
        const message = JSON.parse(event.data) as { type?: string };
        if (message.type === "ack") {
          onProgress({ phase: "done", bytes: blob.size, total: blob.size, rate: 0 });
          cleanup();
          resolve();
        }
      });

      connection.addEventListener("icecandidate", (event) => {
        if (!event.candidate) return;
        void signaller
          .send("candidate", event.candidate.toJSON() as unknown as Record<string, unknown>)
          .catch(() => undefined);
      });

      connection.addEventListener("connectionstatechange", () => {
        if (connection.connectionState === "failed") {
          fail(connectionFailure(relayed));
        }
      });

      const offer = await connection.createOffer();
      await connection.setLocalDescription(offer);
      await signaller.send("offer", { sdp: offer.sdp, type: offer.type });

      try {
        await waitFor(data, "open");
        await pump();
      } catch (error) {
        fail(error instanceof Error ? error : new Error("Transfer failed"));
      }
    };

    signaller.poll((message) => {
      void (async () => {
        try {
          if (message.kind === "hello") {
            await onHello();
            return;
          }

          const connection = pc;
          if (!connection) return;

          if (message.kind === "answer") {
            await connection.setRemoteDescription(
              message.payload as unknown as RTCSessionDescriptionInit,
            );
            remoteSet = true;
            for (const candidate of pendingCandidates.splice(0)) {
              await connection.addIceCandidate(candidate).catch(() => undefined);
            }
            return;
          }

          if (message.kind === "candidate") {
            const candidate = message.payload as unknown as RTCIceCandidateInit;
            if (!remoteSet) pendingCandidates.push(candidate);
            else await connection.addIceCandidate(candidate).catch(() => undefined);
          }
        } catch (error) {
          fail(error instanceof Error ? error : new Error("Handshake failed"));
        }
      })();
    });

    onProgress({ phase: "waiting", bytes: 0, total: blob.size, rate: 0 });
  });

  return {
    finished,
    cancel() {
      cancelled = true;
      cleanup();
      signaller.clear();
    },
  };
}

export interface ReceiveOptions {
  transferId: string;
  token: string;
  sizeBytes: number;
  mimeType: string;
  onProgress(progress: Progress): void;
  /** Defaults to `HttpSignalTransport` against `DEFAULT_SIGNAL_ENDPOINT`. */
  transport?: SignalTransport;
  /** Where to ask for a TURN credential. `null` goes STUN-only. */
  turnEndpoint?: string | null;
}

/**
 * Joins a session and writes the incoming file to disk as it arrives.
 *
 * Every chunk goes into IndexedDB the moment it lands. Nothing is accumulated in
 * memory, which is the only way a phone survives a file bigger than its RAM. When the
 * last chunk is stored the browser assembles a Blob from what is on disk, and the
 * caller hands that to a native download — after which the staging database is erased.
 */
export async function runReceiver(options: ReceiveOptions): Promise<Blob> {
  const { transferId, token, sizeBytes, mimeType, onProgress } = options;
  const signaller = new Signaller(
    options.transport ?? new HttpSignalTransport(transferId, token),
  );
  const store = new ChunkStore(transferId);
  const rate = new Rate();

  await store.init();

  const { servers, relayed } = await iceServers(
    options.turnEndpoint === undefined ? DEFAULT_TURN_ENDPOINT : options.turnEndpoint,
  );
  const connection = new RTCPeerConnection({ iceServers: servers });
  const pendingCandidates: RTCIceCandidateInit[] = [];
  let remoteSet = false;
  let received = 0;
  let index = 0;

  connection.addEventListener("icecandidate", (event) => {
    if (!event.candidate) return;
    void signaller
      .send("candidate", event.candidate.toJSON() as unknown as Record<string, unknown>)
      .catch(() => undefined);
  });

  onProgress({ phase: "connecting", bytes: 0, total: sizeBytes, rate: 0 });

  try {
    const blob = await new Promise<Blob>((resolve, reject) => {
      const fail = (error: Error) => {
        signaller.stop();
        connection.close();
        reject(error);
      };

      connection.addEventListener("connectionstatechange", () => {
        if (connection.connectionState === "failed") {
          fail(connectionFailure(relayed));
        }
      });

      connection.addEventListener("datachannel", (event) => {
        const channel = event.channel;
        channel.binaryType = "arraybuffer";

        // Writes are serialised through this chain so chunks reach IndexedDB in the
        // order SCTP delivered them, without blocking the message handler itself.
        let queue: Promise<void> = Promise.resolve();

        channel.addEventListener("message", (message) => {
          if (typeof message.data === "string") {
            const control = JSON.parse(message.data) as { type?: string };
            if (control.type !== "done") return;

            queue = queue.then(async () => {
              onProgress({ phase: "finishing", bytes: received, total: sizeBytes, rate: 0 });
              const assembled = await store.assemble(mimeType);
              channel.send(JSON.stringify({ type: "ack" }));
              signaller.stop();
              resolve(assembled);
            });
            return;
          }

          const chunk = message.data as ArrayBuffer;
          const at = index;
          index += 1;
          received += chunk.byteLength;

          const bytes = received;
          queue = queue
            .then(() => store.put(at, chunk))
            .then(() => {
              if (at % 16 === 0 || bytes >= sizeBytes) {
                onProgress({
                  phase: "transferring",
                  bytes,
                  total: sizeBytes,
                  rate: rate.update(bytes),
                });
              }
            })
            .catch((error: unknown) =>
              fail(
                error instanceof Error
                  ? new Error(`Could not write to storage: ${error.message}`)
                  : new Error("Could not write to storage"),
              ),
            );
        });

        channel.addEventListener("close", () => {
          if (received < sizeBytes) fail(new Error("The sender disconnected"));
        });
      });

      signaller.poll((envelope) => {
        void (async () => {
          try {
            if (envelope.kind === "offer") {
              await connection.setRemoteDescription(
                envelope.payload as unknown as RTCSessionDescriptionInit,
              );
              remoteSet = true;
              for (const candidate of pendingCandidates.splice(0)) {
                await connection.addIceCandidate(candidate).catch(() => undefined);
              }
              const answer = await connection.createAnswer();
              await connection.setLocalDescription(answer);
              await signaller.send("answer", { sdp: answer.sdp, type: answer.type });
              return;
            }

            if (envelope.kind === "candidate") {
              const candidate = envelope.payload as unknown as RTCIceCandidateInit;
              if (!remoteSet) pendingCandidates.push(candidate);
              else await connection.addIceCandidate(candidate).catch(() => undefined);
            }
          } catch (error) {
            fail(error instanceof Error ? error : new Error("Handshake failed"));
          }
        })();
      });

      // Announces the receiver. The sender is waiting for exactly this before it
      // generates an offer — candidates gathered before anyone is listening go stale.
      void signaller.send("hello", { at: Date.now() }).catch((error: unknown) => {
        fail(error instanceof Error ? error : new Error("Could not reach the sender"));
      });
    });

    connection.close();
    return blob;
  } finally {
    signaller.stop();
  }
}

/**
 * Hands a Blob to the browser as a real download.
 *
 * A native <a download> click, so the file goes through the platform's own download
 * path — the Files app on iOS, the download folder everywhere else — rather than being
 * held open in a tab. The object URL is revoked straight after; keeping it alive would
 * pin the whole blob in memory.
 */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** Erases the session server-side. Called the moment the file is safely saved. */
export async function destroySession(
  transferId: string,
  token?: string,
  endpoint = "/api/transfers",
): Promise<void> {
  const query = token ? `?token=${encodeURIComponent(token)}` : "";
  await fetch(`${endpoint}/${transferId}${query}`, { method: "DELETE" }).catch(
    () => undefined,
  );
}
