/**
 * The call.
 *
 * Everything below runs in the browser and talks to exactly one other browser. There is
 * no server anywhere in this file — no fetch, no socket, no polling. The two session
 * descriptions that let the peers find each other are handed back to the UI as text, and
 * a human carries them across in whatever conversation the two of them already have.
 *
 * That forces one departure from the usual design. Normally a peer connection trickles
 * ICE candidates out as it discovers them, over a signalling channel that stays open.
 * With no channel, the offer has to be complete before it can be copied — so we wait for
 * gathering to finish and ship a single self-contained description. Slower to produce by
 * a second or two, and then nothing further is needed.
 *
 * Once the connection is up, the data channel becomes the signalling channel: any later
 * renegotiation travels inside the encrypted link it is renegotiating. Which also draws
 * the limit of this design honestly — if the transport dies completely, the channel dies
 * with it, and there is no outside path left to repair it. A dropped room cannot be
 * recovered. It has to be opened again.
 *
 * On encryption, plainly: WebRTC is encrypted by the standard and cannot be turned off.
 * Media is SRTP keyed by a DTLS handshake performed between the two browsers, and chat
 * rides the same DTLS association over SCTP. Nobody in the middle — not this app, not
 * Vercel, not the TURN relay if one is used — holds those keys.
 *
 * The one exception to "no server in this file" is the relay lookup, which is a request
 * for a network route and carries nothing about the room.
 */

import { DEFAULT_TURN_ENDPOINT, iceServers } from "./ice.js";

export type CallStatus =
  | "idle"
  | "preparing"
  | "waiting"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "failed"
  | "closed";

export interface ChatLine {
  id: string;
  mine: boolean;
  body: string;
  at: number;
}

export interface MediaState {
  mic: boolean;
  cam: boolean;
  screen: boolean;
}

export interface CallHandlers {
  onStatus?: (status: CallStatus) => void;
  onLocalState?: (state: MediaState) => void;
  onPeerState?: (state: MediaState) => void;
  onChat?: (line: ChatLine) => void;
  onSafetyNumber?: (value: string) => void;
  onNotice?: (message: string) => void;
  /** Fires once the relay has been asked for, so the UI can be honest about reliability. */
  onRelay?: (available: boolean) => void;
}

/** A description this side produced, ready to be carried to the other one. */
export interface Handshake {
  sdp: string;
  fingerprint: string;
}

/** Longer than this is a document, not a message; the UI stops you well before it. */
const CHAT_MAX = 4000;

/**
 * How long to keep collecting network routes before shipping the description.
 *
 * Gathering normally completes in well under a second; a TURN server that is slow or
 * unreachable is what makes it hang. Capping it means a sluggish relay costs a moment
 * rather than the whole room — whatever candidates arrived by then still go in, and
 * they are usually the ones that would have worked anyway.
 */
const ICE_BUDGET_MS = 6000;

/**
 * The three media slots, in the order the host creates them and therefore in the order
 * they appear in the SDP for both sides.
 *
 * Identifying a track by its position rather than by stream id or `mid` string is what
 * keeps this simple. `ontrack` fires during `setRemoteDescription`, long before any
 * negotiated label could be exchanged, so the mapping has to be knowable from the
 * connection alone — and m-line order never changes for the life of a connection.
 */
const SLOT = { audio: 0, camera: 1, screen: 2 } as const;

type Slot = (typeof SLOT)[keyof typeof SLOT];

/**
 * The DTLS certificate fingerprint carried by an SDP blob.
 *
 * Exported because the receiving side must check it against the one that was signed.
 * A signature bound to a fingerprint proves nothing if nobody confirms the connection
 * actually uses that fingerprint.
 */
export function fingerprintOf(sdp: string): string | null {
  const match = /^a=fingerprint:sha-256 ([0-9A-Fa-f:]+)/m.exec(sdp);
  return match?.[1]?.toUpperCase() ?? null;
}

/**
 * What crosses the data channel.
 *
 * `sdp` and `ice` are here so that renegotiation after connection needs no server: the
 * link carries the messages that maintain the link.
 */
type Wire =
  | { t: "chat"; id: string; body: string; at: number }
  | { t: "state"; mic: boolean; cam: boolean; screen: boolean }
  | { t: "bye" }
  | { t: "sdp"; sdp: RTCSessionDescriptionInit }
  | { t: "ice"; candidate: RTCIceCandidateInit };

export class Call {
  /**
   * Four streams built once and never replaced, so a `<video>` element can be bound to
   * one at mount and left alone forever. Tracks come and go inside them.
   *
   * `localCam` deliberately carries only the camera track. Putting your own microphone
   * into a stream you then render is how you end up listening to yourself.
   */
  readonly localCam = new MediaStream();
  readonly localScreen = new MediaStream();
  readonly remoteCam = new MediaStream();
  readonly remoteScreen = new MediaStream();

  private pc: RTCPeerConnection | null = null;
  private channel: RTCDataChannel | null = null;

  /** The guest yields in a collision; the host does not. Somebody has to. */
  private readonly polite: boolean;

  private makingOffer = false;
  private ignoringOffer = false;
  private everConnected = false;
  private closed = false;

  private status: CallStatus = "idle";
  private local: MediaState = { mic: false, cam: false, screen: false };
  private peer: MediaState = { mic: false, cam: false, screen: false };

  private tracks: {
    audio: MediaStreamTrack | null;
    camera: MediaStreamTrack | null;
    screen: MediaStreamTrack | null;
  } = { audio: null, camera: null, screen: null };

  /** Post-connection candidates that arrived before the description they belong to. */
  private earlyCandidates: RTCIceCandidateInit[] = [];

  /** Signalling is strictly ordered, so handlers must not interleave. */
  private queue: Promise<void> = Promise.resolve();

  private safety: string | null = null;

  /** Whether this connection was given a relay. Only known once ICE has been set up. */
  private relayed = false;

  constructor(
    private readonly role: "host" | "guest",
    private readonly handlers: CallHandlers = {},
    /** Where to ask for a TURN credential. `null` goes STUN-only. */
    private readonly turnEndpoint: string | null = DEFAULT_TURN_ENDPOINT,
  ) {
    this.polite = role === "guest";
  }

  // ── the handshake ──────────────────────────────────────────────────────────

  /**
   * Host side. Lays out the connection and produces a complete offer.
   *
   * The three transceivers exist from the first offer so that turning a camera on later
   * is a `replaceTrack` on a sender that is already there — no renegotiation, no
   * flicker, nothing to go wrong mid-call. The guest adopts the same three from the
   * offer and must never add its own, which would push the indices out of step.
   */
  async createOffer(): Promise<Handshake> {
    if (this.role !== "host") throw new Error("Only the host creates the offer");
    this.setStatus("preparing");
    const pc = this.build(await this.ice());

    pc.addTransceiver("audio", { direction: "sendrecv" });
    pc.addTransceiver("video", { direction: "sendrecv" });
    pc.addTransceiver("video", { direction: "sendrecv" });
    this.bindChannel(pc.createDataChannel("otc", { ordered: true }));

    await pc.setLocalDescription(await pc.createOffer());
    await this.gathered(pc);

    return this.describe(pc);
  }

  /**
   * Guest side. Takes the host's offer and produces a complete answer.
   *
   * Anything the guest already switched on — a microphone enabled before the code was
   * generated — is claimed into its slot here, before the answer is written, so it is
   * live the instant the connection opens.
   */
  async answerOffer(offerSdp: string): Promise<Handshake> {
    if (this.role !== "guest") throw new Error("Only the guest answers");
    this.setStatus("preparing");
    const pc = this.build(await this.ice());

    await pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
    await this.claimSlots();
    await pc.setLocalDescription(await pc.createAnswer());
    await this.gathered(pc);

    void this.readSafetyNumber();
    return this.describe(pc);
  }

  /** Host side. The last step: the guest's answer arrives and the connection starts. */
  async acceptAnswer(answerSdp: string): Promise<void> {
    const pc = this.pc;
    if (!pc) throw new Error("No offer has been created yet");
    if (pc.signalingState !== "have-local-offer") return;

    await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
    this.setStatus("connecting");
    void this.readSafetyNumber();
  }

  /** Called by the guest once its code has been handed over, so the UI can move on. */
  awaitConnection(): void {
    if (this.status === "preparing") this.setStatus("connecting");
  }

  private describe(pc: RTCPeerConnection): Handshake {
    const sdp = pc.localDescription?.sdp;
    if (!sdp) throw new Error("The browser produced no session description");

    const fingerprint = fingerprintOf(sdp);
    if (!fingerprint) throw new Error("The browser produced no DTLS fingerprint");

    this.setStatus("waiting");
    return { sdp, fingerprint };
  }

  /**
   * Waits for ICE gathering, but not forever.
   *
   * Resolving early on `complete` is the normal path; the timer only matters when a
   * configured relay is unreachable and would otherwise hold the room hostage.
   */
  private async gathered(pc: RTCPeerConnection): Promise<void> {
    if (pc.iceGatheringState === "complete") return;

    await new Promise<void>((resolve) => {
      let settled = false;

      const finish = () => {
        if (settled) return;
        settled = true;
        pc.removeEventListener("icegatheringstatechange", onChange);
        window.clearTimeout(timer);
        resolve();
      };

      const onChange = () => {
        if (pc.iceGatheringState === "complete") finish();
      };

      const timer = window.setTimeout(finish, ICE_BUDGET_MS);
      pc.addEventListener("icegatheringstatechange", onChange);
    });
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  /**
   * Asks the server for a relay, once, before the connection is built.
   *
   * It has to happen here rather than lazily: `RTCPeerConnection` takes its ICE servers
   * at construction, and by the time an offer is being gathered it is far too late to add
   * one. Each side asks for its own — a relay credential is per-session and neither peer
   * ever sees the other's.
   */
  private async ice(): Promise<RTCIceServer[]> {
    const { servers, relayed } = await iceServers(this.turnEndpoint);
    this.relayed = relayed;
    this.handlers.onRelay?.(relayed);
    return servers;
  }

  private build(servers: RTCIceServer[]): RTCPeerConnection {
    if (this.pc) return this.pc;

    const pc = new RTCPeerConnection({
      iceServers: servers,
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
    });
    this.pc = pc;

    if (this.role === "guest") {
      pc.ondatachannel = (event) => this.bindChannel(event.channel);
    }

    pc.ontrack = this.onTrack;

    /**
     * Before connection these are already inside the description being gathered, so
     * there is nothing to send and nowhere to send it. Afterwards the channel exists
     * and trickling becomes possible again.
     */
    pc.onicecandidate = ({ candidate }) => {
      if (candidate && this.channel?.readyState === "open") {
        this.post({ t: "ice", candidate: candidate.toJSON() });
      }
    };

    pc.onnegotiationneeded = () => {
      // The opening offer is written by hand in `createOffer`; this is only for later.
      if (this.channel?.readyState !== "open") return;
      this.enqueue(async () => {
        try {
          this.makingOffer = true;
          await pc.setLocalDescription();
          if (pc.localDescription) this.post({ t: "sdp", sdp: pc.localDescription });
        } finally {
          this.makingOffer = false;
        }
      });
    };

    pc.onconnectionstatechange = () => {
      switch (pc.connectionState) {
        case "connected":
          this.everConnected = true;
          this.setStatus("connected");
          void this.readSafetyNumber();
          break;
        case "disconnected":
          // Often transient: ICE frequently repairs this without any help.
          this.setStatus("reconnecting");
          break;
        case "failed":
          this.setStatus("failed");
          if (this.channel?.readyState === "open") {
            // The link survives well enough to carry its own repair.
            try {
              pc.restartIce();
            } catch {
              // Nothing left to try from here.
            }
          } else if (this.everConnected) {
            this.handlers.onNotice?.(
              "The connection dropped and there is no server to re-introduce you. Open a new room.",
            );
          }
          break;
        case "closed":
          this.setStatus("closed");
          break;
        default:
          if (this.status !== "connected" && this.status !== "waiting") {
            this.setStatus("connecting");
          }
      }
    };

    return pc;
  }

  /**
   * Ends the call.
   *
   * There is nothing to delete anywhere, because nothing was ever written anywhere. The
   * room is these two tabs; closing one ends it. The parting note over the data channel
   * is a courtesy so the other side sees "left" rather than "reconnecting".
   */
  hangUp(): void {
    if (this.closed) return;
    this.closed = true;

    this.post({ t: "bye" });

    for (const track of Object.values(this.tracks)) track?.stop();
    this.tracks = { audio: null, camera: null, screen: null };
    for (const stream of [
      this.localCam,
      this.localScreen,
      this.remoteCam,
      this.remoteScreen,
    ]) {
      for (const track of stream.getTracks()) stream.removeTrack(track);
    }

    try {
      this.channel?.close();
      this.pc?.close();
    } catch {
      // Already gone.
    }
    this.channel = null;
    this.pc = null;

    this.local = { mic: false, cam: false, screen: false };
    this.handlers.onLocalState?.(this.local);
    this.setStatus("closed");
  }

  get safetyNumber(): string | null {
    return this.safety;
  }

  /** True once a relay has actually been granted for this connection. */
  get hasRelay(): boolean {
    return this.relayed;
  }

  // ── microphone, camera, screen ─────────────────────────────────────────────

  async setMicrophone(on: boolean): Promise<void> {
    if (on === this.local.mic) return;

    if (!on) {
      await this.fill(SLOT.audio, null);
      this.tracks.audio?.stop();
      this.tracks.audio = null;
      this.local = { ...this.local, mic: false };
      this.announce();
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      });
      const track = stream.getAudioTracks()[0] ?? null;
      if (!track) throw new Error("No microphone track");

      this.tracks.audio = track;
      track.addEventListener("ended", () => void this.setMicrophone(false));
      await this.fill(SLOT.audio, track);
      this.local = { ...this.local, mic: true };
      this.announce();
    } catch (error) {
      this.handlers.onNotice?.(describeMediaError(error, "microphone"));
    }
  }

  async setCamera(on: boolean): Promise<void> {
    if (on === this.local.cam) return;

    if (!on) {
      await this.fill(SLOT.camera, null);
      this.tracks.camera?.stop();
      this.tracks.camera = null;
      for (const track of this.localCam.getTracks()) this.localCam.removeTrack(track);
      this.local = { ...this.local, cam: false };
      this.announce();
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          width: { ideal: 1280 },
          height: { ideal: 720 },
          frameRate: { ideal: 30 },
        },
      });
      const track = stream.getVideoTracks()[0] ?? null;
      if (!track) throw new Error("No camera track");

      this.tracks.camera = track;
      track.addEventListener("ended", () => void this.setCamera(false));
      await this.fill(SLOT.camera, track);
      this.localCam.addTrack(track);
      this.local = { ...this.local, cam: true };
      this.announce();
    } catch (error) {
      this.handlers.onNotice?.(describeMediaError(error, "camera"));
    }
  }

  /**
   * Shares a window, tab or whole screen.
   *
   * Audio is left out on purpose: there is one screen slot and it is video. Capturing
   * system sound as well would put a second audio stream into a call that already has
   * a microphone in it, and the result is an echo nobody asked for.
   */
  async setScreen(on: boolean): Promise<void> {
    if (on === this.local.screen) return;

    if (!on) {
      await this.fill(SLOT.screen, null);
      this.tracks.screen?.stop();
      this.tracks.screen = null;
      for (const track of this.localScreen.getTracks()) {
        this.localScreen.removeTrack(track);
      }
      this.local = { ...this.local, screen: false };
      this.announce();
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({
        video: { frameRate: { ideal: 15, max: 30 } },
        audio: false,
      });
      const track = stream.getVideoTracks()[0] ?? null;
      if (!track) throw new Error("No screen track");

      this.tracks.screen = track;
      // The browser draws its own "stop sharing" bar; this is how we hear about it.
      track.addEventListener("ended", () => void this.setScreen(false));
      await this.fill(SLOT.screen, track);
      this.localScreen.addTrack(track);
      this.local = { ...this.local, screen: true };
      this.announce();
    } catch (error) {
      // Dismissing the picker is a decision, not a fault.
      if (error instanceof DOMException && error.name === "NotAllowedError") return;
      this.handlers.onNotice?.(describeMediaError(error, "screen"));
    }
  }

  // ── chat ───────────────────────────────────────────────────────────────────

  sendChat(body: string): boolean {
    const text = body.trim().slice(0, CHAT_MAX);
    if (!text) return false;
    if (this.channel?.readyState !== "open") return false;

    const line: ChatLine = {
      id: crypto.randomUUID(),
      mine: true,
      body: text,
      at: Date.now(),
    };

    this.post({ t: "chat", id: line.id, body: text, at: line.at });
    this.handlers.onChat?.(line);
    return true;
  }

  get chatReady(): boolean {
    return this.channel?.readyState === "open";
  }

  // ── internals ──────────────────────────────────────────────────────────────

  private setStatus(status: CallStatus): void {
    if (this.status === status) return;
    this.status = status;
    this.handlers.onStatus?.(status);
  }

  private post(wire: Wire): void {
    if (this.channel?.readyState !== "open") return;
    try {
      this.channel.send(JSON.stringify(wire));
    } catch {
      // The channel closed between the check and the send.
    }
  }

  private enqueue(job: () => Promise<void>): void {
    this.queue = this.queue.then(job).catch(() => {
      // One bad message must not poison the queue; the connection state machine
      // reports anything that actually matters.
    });
  }

  /** The three negotiated slots, or an empty list before the first offer lands. */
  private slots(): RTCRtpTransceiver[] {
    return this.pc ? this.pc.getTransceivers().slice(0, 3) : [];
  }

  /**
   * Puts a track into its slot, or empties it.
   *
   * `replaceTrack` never triggers renegotiation, which is the whole reason the slots are
   * laid out in advance — and it matters far more here than it would with a signalling
   * server, because renegotiating means writing to a data channel that only exists if
   * the call is already healthy.
   */
  private async fill(slot: Slot, track: MediaStreamTrack | null): Promise<void> {
    const transceiver = this.slots()[slot];
    if (!transceiver) return;
    if (transceiver.direction !== "sendrecv") transceiver.direction = "sendrecv";
    try {
      await transceiver.sender.replaceTrack(track);
    } catch {
      // The connection went away underneath us.
    }
  }

  /**
   * Run by the answering side once the offer has created its transceivers: claim all
   * three for sending and hand over anything already switched on.
   */
  private async claimSlots(): Promise<void> {
    await this.fill(SLOT.audio, this.tracks.audio);
    await this.fill(SLOT.camera, this.tracks.camera);
    await this.fill(SLOT.screen, this.tracks.screen);
  }

  private onTrack = (event: RTCTrackEvent) => {
    const pc = this.pc;
    if (!pc) return;

    const index = pc.getTransceivers().indexOf(event.transceiver);
    const target =
      index === SLOT.screen
        ? this.remoteScreen
        : index === SLOT.audio || index === SLOT.camera
          ? this.remoteCam
          : null;
    if (!target) return;

    const track = event.track;
    for (const existing of target.getTracks()) {
      if (existing.kind === track.kind && existing.id !== track.id) {
        target.removeTrack(existing);
      }
    }
    target.addTrack(track);
    track.addEventListener("ended", () => target.removeTrack(track));
  };

  private bindChannel(channel: RTCDataChannel): void {
    this.channel = channel;

    channel.onopen = () => {
      // Whoever opens first tells the other what is currently switched on.
      this.announce();
    };

    channel.onmessage = (event) => {
      if (typeof event.data !== "string") return;
      let wire: Wire;
      try {
        wire = JSON.parse(event.data) as Wire;
      } catch {
        return;
      }
      this.receive(wire);
    };

    channel.onclose = () => {
      this.peer = { mic: false, cam: false, screen: false };
      this.handlers.onPeerState?.(this.peer);
    };
  }

  private receive(wire: Wire): void {
    switch (wire.t) {
      case "chat":
        if (typeof wire.body !== "string") return;
        this.handlers.onChat?.({
          id: typeof wire.id === "string" ? wire.id : crypto.randomUUID(),
          mine: false,
          body: wire.body.slice(0, CHAT_MAX),
          at: typeof wire.at === "number" ? wire.at : Date.now(),
        });
        return;

      /**
       * What the other side has switched on.
       *
       * Note what this deliberately does *not* do: touch the remote streams. The receiving
       * track for each slot is handed over once, by `ontrack`, during the opening
       * handshake — and because turning a camera or a screen on afterwards is a
       * `replaceTrack`, which by design never renegotiates, `ontrack` never fires a second
       * time. Emptying `remoteScreen` here on the first announcement (which always says
       * screen: false) would therefore throw away the only track this side will ever be
       * given, and no amount of sharing later would bring it back. The stream stays put;
       * `peer.screen` alone decides whether it is on screen.
       */
      case "state":
        this.peer = {
          mic: Boolean(wire.mic),
          cam: Boolean(wire.cam),
          screen: Boolean(wire.screen),
        };
        this.handlers.onPeerState?.(this.peer);
        return;

      case "bye":
        this.handlers.onNotice?.("Your counterparty left the room.");
        this.peer = { mic: false, cam: false, screen: false };
        this.handlers.onPeerState?.(this.peer);
        for (const stream of [this.remoteCam, this.remoteScreen]) {
          for (const track of stream.getTracks()) stream.removeTrack(track);
        }
        return;

      case "sdp":
        this.enqueue(() => this.negotiate(wire.sdp));
        return;

      case "ice":
        this.enqueue(() => this.addCandidate(wire.candidate));
        return;
    }
  }

  /**
   * Perfect negotiation, for anything after the opening handshake.
   *
   * Both sides may decide to renegotiate at the same moment. The impolite peer ignores
   * the clash and presses on; the polite one rolls its own offer back implicitly inside
   * `setRemoteDescription` and answers instead. Exactly one offer survives, always.
   */
  private async negotiate(description: RTCSessionDescriptionInit): Promise<void> {
    const pc = this.pc;
    if (!pc || this.closed || !description.type) return;

    const collision =
      description.type === "offer" && (this.makingOffer || pc.signalingState !== "stable");

    this.ignoringOffer = !this.polite && collision;
    if (this.ignoringOffer) return;

    await pc.setRemoteDescription(description);
    await this.flushCandidates();

    if (description.type === "offer") {
      await pc.setLocalDescription();
      if (pc.localDescription) this.post({ t: "sdp", sdp: pc.localDescription });
    }

    void this.readSafetyNumber();
  }

  private async addCandidate(candidate: RTCIceCandidateInit): Promise<void> {
    const pc = this.pc;
    if (!pc || this.closed || !candidate) return;

    if (!pc.remoteDescription) {
      this.earlyCandidates.push(candidate);
      return;
    }

    try {
      await pc.addIceCandidate(candidate);
    } catch (error) {
      // Expected while an ignored offer is being discarded; anything else is real.
      if (!this.ignoringOffer) throw error;
    }
  }

  private async flushCandidates(): Promise<void> {
    const pc = this.pc;
    if (!pc || this.earlyCandidates.length === 0) return;
    const pending = this.earlyCandidates;
    this.earlyCandidates = [];
    for (const candidate of pending) {
      try {
        await pc.addIceCandidate(candidate);
      } catch {
        // A stale candidate from a previous negotiation.
      }
    }
  }

  private announce(): void {
    this.handlers.onLocalState?.(this.local);
    this.post({
      t: "state",
      mic: this.local.mic,
      cam: this.local.cam,
      screen: this.local.screen,
    });
  }

  /**
   * The number both people read aloud.
   *
   * It is a hash of the two DTLS certificate fingerprints, so it depends on the keys
   * actually in use at both ends and on nothing either side merely claims. If a third
   * party had inserted itself, it would have had to present its own certificate to at
   * least one of you, and the two numbers on screen would not match. Six groups of four
   * hex digits is short enough to say out loud on the call you already have open.
   *
   * With the wallet signatures bound to these same fingerprints, this is now a second
   * check rather than the only one — but it is the one a human can perform unaided, so
   * it stays.
   */
  private async readSafetyNumber(): Promise<void> {
    const pc = this.pc;
    if (!pc) return;

    const mine = fingerprintOf(pc.localDescription?.sdp ?? "");
    const theirs = fingerprintOf(pc.remoteDescription?.sdp ?? "");
    if (!mine || !theirs) return;

    const pair = [mine, theirs].sort().join("|");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pair));
    const hex = [...new Uint8Array(digest).slice(0, 12)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();

    const value = (hex.match(/.{4}/g) ?? []).join(" ");
    if (value === this.safety) return;
    this.safety = value;
    this.handlers.onSafetyNumber?.(value);
  }
}

/** Turns a getUserMedia rejection into something worth reading. */
function describeMediaError(
  error: unknown,
  what: "microphone" | "camera" | "screen",
): string {
  const label = what === "screen" ? "screen sharing" : `the ${what}`;

  if (error instanceof DOMException) {
    switch (error.name) {
      case "NotAllowedError":
        return `Access to ${label} was blocked. Allow it in the address bar and try again.`;
      case "NotFoundError":
      case "OverconstrainedError":
        return `No ${what} was found on this device.`;
      case "NotReadableError":
        return `Another application is holding ${label}. Close it and try again.`;
      case "SecurityError":
        return `Access to ${label} needs a secure connection (https).`;
    }
  }

  return `Could not start ${label}.`;
}
