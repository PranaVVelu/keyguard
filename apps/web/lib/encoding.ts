// kg-auth-v1 canonical signed-message encoding (docs/DECISIONS.md D-001).
// Must produce byte-identical output to services/api/app/security/protocol.py;
// tests/encoding.test.ts checks both against docs/test-vectors/kg-auth-v1.json.

export const PROTOCOL_VERSION = "kg-auth-v1";
export const NONCE_BYTES = 32;
const MAX_FIELD_BYTES = 256;
const utf8 = new TextEncoder();

export const DOMAIN_TAG = new Uint8Array([...utf8.encode("KEYGUARD-AUTH"), 0x00, 0x01]);

export type Action = "unlock" | "lock";

export interface SignedFields {
  vehicleId: string;
  keyId: string;
  challengeId: string;
  nonce: string; // unpadded base64url of NONCE_BYTES random bytes
  action: Action;
  expiresAt: number; // Unix seconds
}

export class EncodingError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict decode: rejects padding, foreign characters and non-canonical trailing bits. */
export function b64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (!B64URL_RE.test(text) || text.length % 4 === 1) throw new EncodingError("BASE64URL_INVALID");
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (b64urlEncode(out) !== text) throw new EncodingError("BASE64URL_INVALID");
  return out;
}

function frame(value: string): Uint8Array {
  const raw = utf8.encode(value);
  if (raw.length === 0 || raw.length > MAX_FIELD_BYTES) throw new EncodingError("FIELD_INVALID");
  const out = new Uint8Array(4 + raw.length);
  new DataView(out.buffer).setUint32(0, raw.length, false);
  out.set(raw, 4);
  return out;
}

export function encodeSignedMessage(f: SignedFields): Uint8Array<ArrayBuffer> {
  if (f.action !== "unlock" && f.action !== "lock") throw new EncodingError("ACTION_INVALID");
  if (!Number.isSafeInteger(f.expiresAt) || f.expiresAt < 0) throw new EncodingError("EXPIRY_INVALID");
  let nonceOk = false;
  try {
    nonceOk = b64urlDecode(f.nonce).length === NONCE_BYTES;
  } catch {
    nonceOk = false;
  }
  if (!nonceOk) throw new EncodingError("NONCE_INVALID");

  const parts = [
    DOMAIN_TAG,
    ...[PROTOCOL_VERSION, f.vehicleId, f.keyId, f.challengeId, f.nonce, f.action, String(f.expiresAt)].map(frame),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// --- kg-fob-v1 (docs/DECISIONS.md D-010): rolling-counter credential, no server challenge -----------

export const FOB_PROTOCOL_VERSION = "kg-fob-v1";
export const FOB_DOMAIN_TAG = new Uint8Array([...utf8.encode("KEYGUARD-FOB"), 0x00, 0x01]);
export const MAX_FOB_COUNTER = Number.MAX_SAFE_INTEGER; // 2^53 − 1, same bound as the server

export interface FobFields {
  vehicleId: string;
  keyId: string;
  counter: number;
  action: Action;
}

/** Same framing as kg-auth-v1 but a different domain tag; checked against docs/test-vectors/kg-fob-v1.json. */
export function encodeFobMessage(f: FobFields): Uint8Array<ArrayBuffer> {
  if (f.action !== "unlock" && f.action !== "lock") throw new EncodingError("ACTION_INVALID");
  if (!Number.isSafeInteger(f.counter) || f.counter < 1) throw new EncodingError("COUNTER_INVALID");
  const parts = [FOB_DOMAIN_TAG, ...[FOB_PROTOCOL_VERSION, f.vehicleId, f.keyId, String(f.counter), f.action].map(frame)];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
