// Parse kg-auth-v1 signed bytes back into labelled segments for the Inspector's hex view.
// Strict: anything that doesn't parse exactly (wrong tag, bad length, trailing bytes) throws.

import { DOMAIN_TAG, toHex } from "./encoding.ts";

export const FIELD_LABELS = [
  "protocol_version",
  "vehicle_id",
  "key_id",
  "challenge_id",
  "nonce",
  "action",
  "expires_at",
] as const;

export interface Segment {
  label: string;
  offset: number;
  /** 4-byte big-endian length prefix as hex; absent for the domain tag. */
  lengthHex?: string;
  valueHex: string;
  /** Printable rendering of the value. */
  text: string;
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

export function annotateSignedMessage(bytes: Uint8Array): Segment[] {
  const tag = bytes.subarray(0, DOMAIN_TAG.length);
  if (toHex(tag) !== toHex(DOMAIN_TAG)) throw new Error("not a kg-auth-v1 message: domain tag mismatch");
  const segments: Segment[] = [
    { label: "domain_tag", offset: 0, valueHex: toHex(tag), text: 'KEYGUARD-AUTH \\x00 \\x01 (tag, separator, format v1)' },
  ];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = DOMAIN_TAG.length;
  for (const label of FIELD_LABELS) {
    if (off + 4 > bytes.length) throw new Error(`truncated before ${label}`);
    const len = view.getUint32(off, false);
    const start = off + 4;
    if (start + len > bytes.length) throw new Error(`length of ${label} overruns message`);
    const value = bytes.subarray(start, start + len);
    segments.push({
      label,
      offset: off,
      lengthHex: toHex(bytes.subarray(off, start)),
      valueHex: toHex(value),
      text: utf8.decode(value),
    });
    off = start + len;
  }
  if (off !== bytes.length) throw new Error("trailing bytes after last field");
  return segments;
}

/** Split a 64-byte P1363 signature into its r and s halves (hex). */
export function splitSignature(sig: Uint8Array): { r: string; s: string } {
  if (sig.length !== 64) throw new Error("expected a 64-byte P1363 signature");
  return { r: toHex(sig.subarray(0, 32)), s: toHex(sig.subarray(32)) };
}
