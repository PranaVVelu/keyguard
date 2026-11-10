import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { annotateSignedMessage, FIELD_LABELS, splitSignature } from "../lib/annotate.ts";
import { b64urlDecode } from "../lib/encoding.ts";

const VECTORS = JSON.parse(
  readFileSync(new URL("../../../docs/test-vectors/kg-auth-v1.json", import.meta.url), "utf8"),
);
const hexToBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));

for (const vec of VECTORS.encoding) {
  test(`annotates vector "${vec.name}" back into its exact fields`, () => {
    const bytes = hexToBytes(vec.message_hex);
    const segs = annotateSignedMessage(bytes);
    assert.deepEqual(segs.map((s) => s.label), ["domain_tag", ...FIELD_LABELS]);
    const values = Object.fromEntries(segs.slice(1).map((s) => [s.label, s.text]));
    assert.equal(values.protocol_version, "kg-auth-v1");
    assert.equal(values.vehicle_id, vec.fields.vehicle_id);
    assert.equal(values.key_id, vec.fields.key_id);
    assert.equal(values.challenge_id, vec.fields.challenge_id);
    assert.equal(values.nonce, vec.fields.nonce);
    assert.equal(values.action, vec.fields.action);
    assert.equal(values.expires_at, String(vec.fields.expires_at));
    // Segments tile the message exactly: tag + (4-byte length + value) per field.
    const total = segs.reduce((n, s) => n + (s.lengthHex?.length ?? 0) / 2 + s.valueHex.length / 2, 0);
    assert.equal(total, bytes.length);
  });
}

test("rejects wrong domain tag, truncation and trailing bytes", () => {
  const good = hexToBytes(VECTORS.encoding[0].message_hex);
  const badTag = good.slice();
  badTag[0] ^= 0xff;
  assert.throws(() => annotateSignedMessage(badTag), /domain tag/);
  assert.throws(() => annotateSignedMessage(good.subarray(0, good.length - 3)), /overruns|truncated/);
  const trailing = new Uint8Array([...good, 0x00]);
  assert.throws(() => annotateSignedMessage(trailing), /trailing/);
});

test("splits a P1363 signature into r and s", () => {
  const sig = b64urlDecode(VECTORS.verify.cases[0].signature);
  const { r, s } = splitSignature(sig);
  assert.equal(r.length, 64);
  assert.equal(s.length, 64);
  assert.throws(() => splitSignature(sig.subarray(0, 63)));
});
