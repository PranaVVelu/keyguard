// Browser half of passkey sign-in (D-012). Converts the server's JSON options to WebAuthn's binary form and the
// resulting credential back to JSON. Uses the native JSON helpers when the browser has them.

import { b64urlDecode, b64urlEncode } from "./encoding.ts";

type Json = Record<string, unknown>;
const buf = (b64: string) => b64urlDecode(b64).buffer;

export function creationOptionsFromJSON(o: Json): PublicKeyCredentialCreationOptions {
  const user = o.user as Json;
  return {
    ...(o as unknown as PublicKeyCredentialCreationOptions),
    challenge: buf(o.challenge as string),
    user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: buf(user.id as string) },
    excludeCredentials: ((o.excludeCredentials as Json[] | undefined) ?? []).map((c) => ({
      ...(c as unknown as PublicKeyCredentialDescriptor),
      id: buf(c.id as string),
    })),
  };
}

export function requestOptionsFromJSON(o: Json): PublicKeyCredentialRequestOptions {
  return {
    ...(o as unknown as PublicKeyCredentialRequestOptions),
    challenge: buf(o.challenge as string),
    allowCredentials: ((o.allowCredentials as Json[] | undefined) ?? []).map((c) => ({
      ...(c as unknown as PublicKeyCredentialDescriptor),
      id: buf(c.id as string),
    })),
  };
}

const enc = (b: ArrayBuffer | null | undefined) => (b ? b64urlEncode(new Uint8Array(b)) : undefined);

/** PublicKeyCredential → the JSON shape py_webauthn expects. */
export function credentialToJSON(cred: PublicKeyCredential): Json {
  const r = cred.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const response: Json = { clientDataJSON: enc(r.clientDataJSON) };
  if ("attestationObject" in r && r.attestationObject) {
    response.attestationObject = enc(r.attestationObject);
    response.transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  } else {
    response.authenticatorData = enc(r.authenticatorData);
    response.signature = enc(r.signature);
    const handle = enc(r.userHandle);
    if (handle) response.userHandle = handle;
  }
  return {
    id: cred.id,
    rawId: enc(cred.rawId),
    type: cred.type,
    response,
    clientExtensionResults: cred.getClientExtensionResults(),
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
  };
}

export async function createPasskey(options: Json): Promise<Json> {
  const cred = (await navigator.credentials.create({ publicKey: creationOptionsFromJSON(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was created");
  return credentialToJSON(cred);
}

export async function getPasskey(options: Json): Promise<Json> {
  const cred = (await navigator.credentials.get({ publicKey: requestOptionsFromJSON(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was selected");
  return credentialToJSON(cred);
}

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && window.isSecureContext;
}
