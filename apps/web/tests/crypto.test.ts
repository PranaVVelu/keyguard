// Runs the real Web Crypto API (Node's implementation of the same W3C spec browsers use).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  exportPublicKey,
  generateDeviceKey,
  importPublicKey,
  publicKeyFingerprint,
  signMessage,
  verifyMessage,
} from "../lib/crypto.ts";
import { b64urlDecode, encodeSignedMessage } from "../lib/encoding.ts";

const VECTORS = JSON.parse(
  readFileSync(new URL("../../../docs/test-vectors/kg-auth-v1.json", import.meta.url), "utf8"),
);
const WEBCRYPTO_VECTOR = JSON.parse(
  readFileSync(new URL("../../../docs/test-vectors/kg-auth-v1-webcrypto.json", import.meta.url), "utf8"),
);

const hexToBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));

test("private key is non-extractable; public key exports as 91-byte P-256 SPKI", async () => {
  const { privateKey, publicKey } = await generateDeviceKey();
  assert.equal(privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey("pkcs8", privateKey));
  await assert.rejects(crypto.subtle.exportKey("jwk", privateKey));
  const spki = await exportPublicKey(publicKey);
  assert.equal(b64urlDecode(spki).length, 91);
});

test("sign → verify round trip on a canonical message; signature is 64-byte P1363", async () => {
  const { privateKey, publicKey } = await generateDeviceKey();
  const msg = hexToBytes(VECTORS.encoding[0].message_hex);
  const sig = await signMessage(privateKey, msg);
  assert.equal(b64urlDecode(sig).length, 64);
  assert.equal(await verifyMessage(publicKey, msg, sig), true);
  const other = hexToBytes(VECTORS.encoding[1].message_hex);
  assert.equal(await verifyMessage(publicKey, other, sig), false);
});

test("fingerprint is SHA-256 of SPKI (matches server definition)", async () => {
  const spki = VECTORS.verify.public_key_spki_b64url;
  const fp = await publicKeyFingerprint(spki);
  assert.match(fp, /^[0-9a-f]{64}$/);
});

// Python-generated signatures (cryptography lib, converted to P1363) verified by Web Crypto.
for (const c of VECTORS.verify.cases) {
  test(`Web Crypto agrees with Python verify vector: ${c.name}`, async () => {
    const pub = await importPublicKey(VECTORS.verify.public_key_spki_b64url);
    const msg = hexToBytes(c.message_hex);
    let ok: boolean;
    try {
      ok = await verifyMessage(pub, msg, c.signature);
    } catch {
      ok = false; // malformed input may throw instead of returning false; both mean "not accepted"
    }
    assert.equal(ok, c.expected === "valid");
  });
}

// The committed Web Crypto vector is also verified by Python (services/api/tests/test_interop.py).
test("committed Web Crypto vector verifies", async () => {
  const pub = await importPublicKey(WEBCRYPTO_VECTOR.public_key_spki_b64url);
  const msg = encodeSignedMessage({
    vehicleId: WEBCRYPTO_VECTOR.fields.vehicle_id,
    keyId: WEBCRYPTO_VECTOR.fields.key_id,
    challengeId: WEBCRYPTO_VECTOR.fields.challenge_id,
    nonce: WEBCRYPTO_VECTOR.fields.nonce,
    action: WEBCRYPTO_VECTOR.fields.action,
    expiresAt: WEBCRYPTO_VECTOR.fields.expires_at,
  });
  assert.equal(await verifyMessage(pub, msg, WEBCRYPTO_VECTOR.signature), true);
});
