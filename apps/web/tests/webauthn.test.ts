import assert from "node:assert/strict";
import { test } from "node:test";

import { b64urlEncode } from "../lib/encoding.ts";
import { creationOptionsFromJSON, credentialToJSON, requestOptionsFromJSON } from "../lib/webauthn.ts";

const bytes = (n: number, fill: number) => new Uint8Array(n).fill(fill);

test("creation options: challenge and user.id become binary, everything else is kept", () => {
  const o = creationOptionsFromJSON({
    challenge: b64urlEncode(bytes(32, 7)),
    rp: { id: "localhost", name: "KeyGuard" },
    user: { id: b64urlEncode(bytes(32, 9)), name: "Ana", displayName: "Ana" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  assert.deepEqual(new Uint8Array(o.challenge as ArrayBuffer), bytes(32, 7));
  assert.deepEqual(new Uint8Array(o.user.id as ArrayBuffer), bytes(32, 9));
  assert.equal(o.rp.id, "localhost");
  assert.equal(o.authenticatorSelection?.residentKey, "required");
  assert.deepEqual(o.excludeCredentials, []);
});

test("request options: no allowCredentials stays empty (discoverable sign-in)", () => {
  const o = requestOptionsFromJSON({ challenge: b64urlEncode(bytes(32, 1)), userVerification: "required" });
  assert.deepEqual(o.allowCredentials, []);
  assert.equal(o.userVerification, "required");
});

test("assertion credential serialises to the JSON the server verifies", () => {
  const ab = (n: number, f: number) => bytes(n, f).buffer;
  const cred = {
    id: b64urlEncode(bytes(16, 3)),
    rawId: ab(16, 3),
    type: "public-key",
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({}),
    response: { clientDataJSON: ab(10, 1), authenticatorData: ab(37, 2), signature: ab(70, 4), userHandle: ab(32, 5) },
  } as unknown as PublicKeyCredential;
  const json = credentialToJSON(cred) as { rawId: string; response: Record<string, string> };
  assert.equal(json.rawId, b64urlEncode(bytes(16, 3)));
  assert.equal(json.response.signature, b64urlEncode(bytes(70, 4)));
  assert.equal(json.response.userHandle, b64urlEncode(bytes(32, 5)));
  assert.equal(json.response.attestationObject, undefined);
});

test("attestation credential includes the attestation object and transports", () => {
  const cred = {
    id: "x", rawId: bytes(1, 1).buffer, type: "public-key", authenticatorAttachment: null,
    getClientExtensionResults: () => ({}),
    response: { clientDataJSON: bytes(4, 1).buffer, attestationObject: bytes(8, 2).buffer, getTransports: () => ["internal"] },
  } as unknown as PublicKeyCredential;
  const json = credentialToJSON(cred) as { response: Record<string, unknown> };
  assert.equal(json.response.attestationObject, b64urlEncode(bytes(8, 2)));
  assert.deepEqual(json.response.transports, ["internal"]);
});
