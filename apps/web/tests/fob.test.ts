import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { afterEach, test } from "node:test";

import { cardTapAction, performFobPress } from "../lib/auth-flow.ts";
import { generateDeviceKey, importPublicKey, verifyMessage } from "../lib/crypto.ts";
import {
  DOMAIN_TAG,
  encodeFobMessage,
  encodeSignedMessage,
  FOB_DOMAIN_TAG,
  MAX_FOB_COUNTER,
  toHex,
  type Action,
} from "../lib/encoding.ts";

const VECTORS = JSON.parse(readFileSync(new URL("../../../docs/test-vectors/kg-fob-v1.json", import.meta.url), "utf8"));
const hexToBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
const fromPy = (f: { vehicle_id: string; key_id: string; counter: number; action: Action }) => ({
  vehicleId: f.vehicle_id,
  keyId: f.key_id,
  counter: f.counter,
  action: f.action,
});

test("fob domain tag matches the Python vectors and differs from kg-auth-v1", () => {
  assert.equal(toHex(FOB_DOMAIN_TAG), VECTORS.domain_tag_hex);
  assert.notEqual(toHex(FOB_DOMAIN_TAG), toHex(DOMAIN_TAG));
});

for (const vec of VECTORS.encoding) {
  test(`kg-fob-v1 encoding matches Python: ${vec.name}`, () => {
    assert.equal(toHex(encodeFobMessage(fromPy(vec.fields))), vec.message_hex);
  });
}

for (const c of VECTORS.verify.cases) {
  test(`Web Crypto agrees with Python fob verify vector: ${c.name}`, async () => {
    const pub = await importPublicKey(VECTORS.verify.public_key_spki_b64url);
    assert.equal(await verifyMessage(pub, hexToBytes(c.message_hex), c.signature), c.expected);
  });
}

for (const bad of [0, -1, 1.5, MAX_FOB_COUNTER + 1, Number.NaN]) {
  test(`rejects counter ${bad}`, () => {
    assert.throws(
      () => encodeFobMessage({ vehicleId: "veh_x", keyId: "key_x", counter: bad, action: "unlock" }),
      { code: "COUNTER_INVALID" },
    );
  });
}

test("a fob message can never equal a challenge message", () => {
  const fob = encodeFobMessage({ vehicleId: "veh_x", keyId: "key_x", counter: 1, action: "unlock" });
  const chl = encodeSignedMessage({
    vehicleId: "veh_x", keyId: "key_x", challengeId: "chl_x",
    nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", action: "unlock", expiresAt: 1,
  });
  assert.notEqual(toHex(fob.subarray(0, 15)), toHex(chl.subarray(0, 15)));
});

// --- performFobPress: counter reserved before signing, signature verifies over the sent fields -------

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

test("fob press reserves the counter first, then signs exactly what it sends", async () => {
  const { privateKey, publicKey } = await generateDeviceKey();
  const order: string[] = [];
  let sent: Record<string, unknown> | null = null;
  globalThis.fetch = async (_url, init) => {
    order.push("send");
    sent = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({ decision: "allow", reason: null, key_id: "key_x", vehicle_id: "veh_x", action: "unlock",
        counter: 7, last_counter: 7, lock_state: "unlocked", duration_ms: 1, trace: [] }),
      { status: 200 },
    );
  };
  const press = await performFobPress(
    { labId: "lab_x", labToken: "t", expiresAt: 0 },
    { vehicleId: "veh_x", keyId: "key_x", action: "unlock" },
    privateKey,
    async () => {
      order.push("reserve");
      return 7;
    },
  );
  assert.deepEqual(order, ["reserve", "send"]);
  assert.equal(press.counter, 7);
  assert.deepEqual(
    { ...sent!, signature: undefined },
    { vehicle_id: "veh_x", key_id: "key_x", action: "unlock", counter: 7, signature: undefined },
  );
  const expected = encodeFobMessage({ vehicleId: "veh_x", keyId: "key_x", counter: 7, action: "unlock" });
  assert.ok(await verifyMessage(publicKey, expected, String(sent!.signature)));
});

test("a failed counter reservation sends nothing", async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return new Response("{}");
  };
  const { privateKey } = await generateDeviceKey();
  await assert.rejects(
    performFobPress({ labId: "lab_x", labToken: "t", expiresAt: 0 }, { vehicleId: "v", keyId: "k", action: "lock" },
      privateKey, async () => { throw new Error("not a fob"); }),
  );
  assert.equal(called, false);
});

test("a key card tap asks for the opposite of the backend lock state", () => {
  assert.equal(cardTapAction("locked"), "unlock");
  assert.equal(cardTapAction("unlocked"), "lock");
});
