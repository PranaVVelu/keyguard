import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import type { Challenge } from "../lib/api.ts";
import { ClientRefusal, signedMessageFor } from "../lib/auth-flow.ts";
import { toHex } from "../lib/encoding.ts";

const VECTORS = JSON.parse(
  readFileSync(new URL("../../../docs/test-vectors/kg-auth-v1.json", import.meta.url), "utf8"),
);
const f = VECTORS.encoding[0].fields;

const CHALLENGE: Challenge = {
  protocol_version: "kg-auth-v1",
  challenge_id: f.challenge_id,
  vehicle_id: f.vehicle_id,
  key_id: f.key_id,
  nonce: f.nonce,
  action: f.action,
  expires_at: f.expires_at,
};
const REQUEST = { vehicleId: f.vehicle_id, keyId: f.key_id, action: f.action };

test("signs exactly the canonical bytes for a matching challenge", () => {
  assert.equal(toHex(signedMessageFor(REQUEST, CHALLENGE)), VECTORS.encoding[0].message_hex);
});

const MISMATCHES: [string, Partial<Challenge>][] = [
  ["action swapped by server", { action: "lock" }],
  ["different vehicle", { vehicle_id: "veh_ZZZZZZZZZZZZZZZZZZZZZZ" }],
  ["different key", { key_id: "key_ZZZZZZZZZZZZZZZZZZZZZZ" }],
];
for (const [name, override] of MISMATCHES) {
  test(`refuses to sign: ${name}`, () => {
    assert.throws(
      () => signedMessageFor(REQUEST, { ...CHALLENGE, ...override }),
      (e: unknown) => e instanceof ClientRefusal && e.code === "CHALLENGE_MISMATCH",
    );
  });
}

test("refuses an unknown protocol version", () => {
  assert.throws(
    () => signedMessageFor(REQUEST, { ...CHALLENGE, protocol_version: "kg-auth-v2" as never }),
    (e: unknown) => e instanceof ClientRefusal && e.code === "PROTOCOL_MISMATCH",
  );
});
