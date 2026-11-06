// Client-side key handling with the Web Crypto API (spec §4: private keys never leave the browser).
// Note: a non-extractable browser key is NOT equivalent to a hardware-backed automotive credential.

import { b64urlDecode, b64urlEncode, toHex } from "./encoding.ts";

const ALGORITHM: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_PARAMS: EcdsaParams = { name: "ECDSA", hash: "SHA-256" };

/** P-256 key pair whose private half cannot be exported, even by this app's own code. */
export async function generateDeviceKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ALGORITHM, false, ["sign", "verify"]);
}

/** SPKI DER, unpadded base64url: the only key material ever sent to the server. */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  return b64urlEncode(new Uint8Array(await crypto.subtle.exportKey("spki", publicKey)));
}

/** SHA-256 of the SPKI bytes, hex. It matches the server's `fingerprint` field. */
export async function publicKeyFingerprint(spkiB64url: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b64urlDecode(spkiB64url))));
}

/** Web Crypto ECDSA signatures are IEEE P1363 `r||s` (64 bytes), which is exactly the kg-auth-v1 wire format. */
export async function signMessage(privateKey: CryptoKey, message: Uint8Array<ArrayBuffer>): Promise<string> {
  return b64urlEncode(new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS, privateKey, message)));
}

export async function importPublicKey(spkiB64url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", b64urlDecode(spkiB64url), ALGORITHM, true, ["verify"]);
}

export async function verifyMessage(
  publicKey: CryptoKey,
  message: Uint8Array<ArrayBuffer>,
  signatureB64url: string,
): Promise<boolean> {
  return crypto.subtle.verify(SIGN_PARAMS, publicKey, b64urlDecode(signatureB64url), message);
}
