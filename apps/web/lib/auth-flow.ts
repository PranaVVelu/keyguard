// Client half of kg-auth-v1: request a challenge, check it is the one we asked for, sign it, submit.
// The UI shows only the server's Decision; nothing here decides whether the vehicle unlocked.

import type { Action, Challenge } from "./api.ts";
import { encodeSignedMessage, PROTOCOL_VERSION } from "./encoding.ts";

export interface ActionRequest {
  vehicleId: string;
  keyId: string;
  action: Action;
}

export class ClientRefusal extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * Build the bytes to sign, refusing any challenge that doesn't match what the user asked for.
 * This stops a buggy or malicious server from getting, say, an "unlock" signature
 * when the user pressed "lock".
 */
export function signedMessageFor(req: ActionRequest, chl: Challenge): Uint8Array<ArrayBuffer> {
  if (chl.protocol_version !== PROTOCOL_VERSION) {
    throw new ClientRefusal("PROTOCOL_MISMATCH", `Unsupported protocol ${chl.protocol_version}`);
  }
  const mismatched = (
    [
      ["vehicle_id", chl.vehicle_id, req.vehicleId],
      ["key_id", chl.key_id, req.keyId],
      ["action", chl.action, req.action],
    ] as const
  ).filter(([, got, want]) => got !== want);
  if (mismatched.length > 0) {
    throw new ClientRefusal(
      "CHALLENGE_MISMATCH",
      `Refusing to sign: challenge ${mismatched.map(([f]) => f).join(", ")} differs from the request`,
    );
  }
  return encodeSignedMessage({
    vehicleId: chl.vehicle_id,
    keyId: chl.key_id,
    challengeId: chl.challenge_id,
    nonce: chl.nonce,
    action: chl.action,
    expiresAt: chl.expires_at,
  });
}
