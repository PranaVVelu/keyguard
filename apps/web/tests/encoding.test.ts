import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  b64urlDecode,
  b64urlEncode,
  DOMAIN_TAG,
  EncodingError,
  encodeSignedMessage,
  toHex,
  type SignedFields,
} from "../lib/encoding.ts";

const VECTORS = JSON.parse(
  readFileSync(new URL("../../../docs/test-vectors/kg-auth-v1.json", import.meta.url), "utf8"),
);

interface PyFields {
  vehicle_id: string;
  key_id: string;
  challenge_id: string;
  nonce: string;
  action: "unlock" | "lock";
  expires_at: number;
}

export function fromPy(f: PyFields): SignedFields {
  return {
    vehicleId: f.vehicle_id,
    keyId: f.key_id,
    challengeId: f.challenge_id,
    nonce: f.nonce,
    action: f.action,
    expiresAt: f.expires_at,
  };
}

const BASE = fromPy(VECTORS.encoding[0].fields);

for (const vec of VECTORS.encoding) {
  test(`encoding matches Python vector: ${vec.name}`, () => {
    assert.equal(toHex(encodeSignedMessage(fromPy(vec.fields))), vec.message_hex);
  });
}

test("domain tag matches", () => {
  assert.equal(toHex(DOMAIN_TAG), VECTORS.domain_tag_hex);
});

test("framing prevents field-boundary collisions", () => {
  const a = encodeSignedMessage({ ...BASE, vehicleId: "veh_AB", keyId: "Ckey" });
  const b = encodeSignedMessage({ ...BASE, vehicleId: "veh_A", keyId: "BCkey" });
  assert.notEqual(toHex(a), toHex(b));
});

const INVALID: [string, Partial<SignedFields>, string][] = [
  ["unknown action", { action: "open_trunk" as never }, "ACTION_INVALID"],
  ["negative expiry", { expiresAt: -1 }, "EXPIRY_INVALID"],
  ["fractional expiry", { expiresAt: 1.5 }, "EXPIRY_INVALID"],
  ["short nonce", { nonce: b64urlEncode(new Uint8Array(31)) }, "NONCE_INVALID"],
  ["padded nonce", { nonce: b64urlEncode(new Uint8Array(32)) + "=" }, "NONCE_INVALID"],
  ["empty field", { vehicleId: "" }, "FIELD_INVALID"],
  ["oversized field", { keyId: "x".repeat(257) }, "FIELD_INVALID"],
];
for (const [name, override, code] of INVALID) {
  test(`encoder rejects ${name}`, () => {
    assert.throws(
      () => encodeSignedMessage({ ...BASE, ...override }),
      (e: unknown) => e instanceof EncodingError && e.code === code,
    );
  });
}

for (const bad of ["AAA=", "AA+A", "AA/A", "A", "AB", " AAAA"]) {
  test(`b64url decode is strict: ${JSON.stringify(bad)}`, () => {
    assert.throws(() => b64urlDecode(bad), EncodingError);
  });
}
