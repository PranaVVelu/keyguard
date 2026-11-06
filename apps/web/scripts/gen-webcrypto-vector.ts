// Generates docs/test-vectors/kg-auth-v1-webcrypto.json: a key pair and signature produced by
// Web Crypto through lib/crypto.ts, which the Python test suite must verify.
// Run once and commit:  node scripts/gen-webcrypto-vector.ts

import { readFileSync, writeFileSync } from "node:fs";

import { exportPublicKey, generateDeviceKey, signMessage } from "../lib/crypto.ts";
import { encodeSignedMessage, toHex } from "../lib/encoding.ts";

const vectors = JSON.parse(
  readFileSync(new URL("../../../docs/test-vectors/kg-auth-v1.json", import.meta.url), "utf8"),
);
const fields = vectors.encoding[0].fields;

const { privateKey, publicKey } = await generateDeviceKey();
const message = encodeSignedMessage({
  vehicleId: fields.vehicle_id,
  keyId: fields.key_id,
  challengeId: fields.challenge_id,
  nonce: fields.nonce,
  action: fields.action,
  expiresAt: fields.expires_at,
});

const out = {
  protocol: "kg-auth-v1",
  generator: `Web Crypto via apps/web/lib/crypto.ts (Node ${process.version})`,
  public_key_spki_b64url: await exportPublicKey(publicKey),
  fields,
  message_hex: toHex(message),
  signature: await signMessage(privateKey, message),
};

const path = new URL("../../../docs/test-vectors/kg-auth-v1-webcrypto.json", import.meta.url);
writeFileSync(path, JSON.stringify(out, null, 2) + "\n");
console.log(`wrote ${path.pathname}`);
