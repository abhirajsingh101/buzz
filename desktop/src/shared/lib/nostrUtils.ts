import { decode, npubEncode } from "nostr-tools/nip19";
import { getPublicKey } from "nostr-tools/pure";

/**
 * Convert a hex-encoded Nostr public key to its npub (bech32) representation.
 *
 * @param hexPubkey — 64-character hex string
 * @returns npub1… bech32-encoded public key
 */
export function pubkeyToNpub(hexPubkey: string): string {
  return npubEncode(hexPubkey);
}

/**
 * Like `pubkeyToNpub`, but returns null instead of throwing on malformed
 * input. For display surfaces that must degrade gracefully.
 */
export function safeNpub(pubkey: string): string | null {
  try {
    return npubEncode(pubkey);
  } catch {
    return null;
  }
}

const HEX_PUBKEY_REGEX = /^[0-9a-f]{64}$/;

/**
 * Parse user-entered public key input — either a 64-character hex pubkey or
 * a bech32 `npub1…` string — into a lowercase hex pubkey. Returns null for
 * anything else (does NOT throw — intended for live form validation).
 *
 * The input is trimmed first; surrounding whitespace from copy-paste is
 * tolerated.
 */
export function parsePubkeyInput(input: string): string | null {
  const trimmed = input.trim().toLowerCase();
  if (HEX_PUBKEY_REGEX.test(trimmed)) {
    return trimmed;
  }
  if (trimmed.startsWith("npub1")) {
    try {
      const decoded = decode(trimmed);
      if (decoded.type === "npub") {
        return decoded.data;
      }
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Decode a bech32 nsec string and derive the matching npub. Returns null if
 * the input is not a syntactically valid `nsec1…` (does NOT throw — this is
 * intended for live form validation where the user is mid-typing).
 *
 * The input is trimmed first; surrounding whitespace from copy-paste or a
 * dropped `.key` file is tolerated.
 */
export function nsecToNpub(nsec: string): string | null {
  const pubkeyHex = nsecToPubkeyHex(nsec);
  return pubkeyHex === null ? null : safeNpub(pubkeyHex);
}

/**
 * Decode a bech32 nsec string and derive the matching hex pubkey. Returns null
 * if the input is not a syntactically valid `nsec1…` (does NOT throw — this is
 * intended for live form validation where the user is mid-typing).
 *
 * bech32 only, deliberately: a 64-character hex *public* key is also a
 * syntactically valid *secret* key, so accepting hex here would let a pasted
 * pubkey be treated as an identity nobody holds the key to. The `nsec1` prefix
 * is the only thing that distinguishes them, and the backend refuses hex for
 * the same reason (`resolve_agent_keys`).
 *
 * The input is trimmed first; surrounding whitespace from copy-paste or a
 * dropped `.key` file is tolerated.
 */
export function nsecToPubkeyHex(nsec: string): string | null {
  const trimmed = nsec.trim();
  if (!trimmed.startsWith("nsec1")) {
    return null;
  }
  try {
    const decoded = decode(trimmed);
    if (decoded.type !== "nsec") {
      return null;
    }
    return getPublicKey(decoded.data);
  } catch {
    return null;
  }
}
