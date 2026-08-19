/**
 * Where two browsers look for a path to each other.
 *
 * STUN discovers your public address, and for most pairs of home networks that is the whole
 * job. It is not enough between two symmetric NATs — mobile carriers, corporate and campus
 * wifi — where nothing direct can be negotiated at all and a TURN relay forwarding the
 * packets is the only fix. The relay cannot read them: it moves sealed DTLS records and
 * holds none of the keys. It does see both IP addresses, which is worth saying out loud
 * rather than switching on quietly.
 *
 * The relay credential is fetched rather than compiled in. A credential in the bundle is a
 * permanent one published to every visitor, which cannot gate bandwidth somebody pays for
 * by the gigabyte. Point `endpoint` at a route of your own that mints a short-lived one.
 *
 * A refusal is not a failure. Without a relay you still get the STUN list and a direct
 * connection, which is what the great majority of transfers and calls use anyway.
 */

const STUN: RTCIceServer = {
  urls: [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
  ],
};

export interface IceConfig {
  servers: RTCIceServer[];
  /** True only if a relay was actually granted. */
  relayed: boolean;
}

/** What a TURN endpoint is expected to answer with. Anything else is treated as a refusal. */
export interface TurnGrant {
  urls: string[];
  username: string;
  credential: string;
}

export const DEFAULT_TURN_ENDPOINT = "/api/turn";

/**
 * Asks for a relay, once, before a connection is built.
 *
 * It has to happen before construction rather than lazily: `RTCPeerConnection` takes its
 * ICE servers as constructor arguments, and by the time candidates are being gathered it is
 * far too late to add one. Each side asks for its own — a credential is per-session and
 * neither peer ever sees the other's.
 *
 * Pass `null` to skip the request entirely and go STUN-only.
 */
export async function iceServers(
  endpoint: string | null = DEFAULT_TURN_ENDPOINT,
): Promise<IceConfig> {
  const servers: RTCIceServer[] = [STUN];
  if (!endpoint) return { servers, relayed: false };

  try {
    const res = await fetch(endpoint, { cache: "no-store" });
    if (!res.ok) return { servers, relayed: false };

    const body = (await res.json()) as {
      urls?: unknown;
      username?: unknown;
      credential?: unknown;
    };

    const urls = Array.isArray(body.urls)
      ? body.urls.filter((value): value is string => typeof value === "string")
      : [];

    if (
      urls.length > 0 &&
      typeof body.username === "string" &&
      typeof body.credential === "string"
    ) {
      servers.push({ urls, username: body.username, credential: body.credential });
      return { servers, relayed: true };
    }
  } catch {
    // Offline, or the route is unreachable. A direct connection is still worth trying.
  }

  return { servers, relayed: false };
}
