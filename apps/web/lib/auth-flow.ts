// Client half of kg-auth-v1: request a challenge, check it is the one we asked for, sign it, submit.
// The UI shows only the server's Decision; nothing here decides whether the vehicle unlocked.

import { authenticate, issueChallenge, pressFob, type Action, type Challenge, type Decision, type FobDecision } from "./api.ts";
import { signMessage } from "./crypto.ts";
import { encodeFobMessage, encodeSignedMessage, PROTOCOL_VERSION } from "./encoding.ts";
import { reserveFobCounter } from "./keystore.ts";
import type { LabSession } from "./lab-session.ts";

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

// --- Full client flow, reporting each stage (used by the Garage and the Inspector) ---------------


export interface FlowArtifacts {
  request: ActionRequest;
  challenge?: Challenge;
  message?: Uint8Array<ArrayBuffer>;
  signature?: string;
  decision?: Decision;
  timings: Partial<Record<FlowStage, number>>; // ms spent in each stage, measured in the browser
}

export type FlowStage = "challenge" | "check" | "sign" | "verify";

/**
 * challenge → check → sign → verify. `onStage` fires after each stage with everything gathered so far,
 * so the UI can render real artifacts as they arrive. Throws ApiError or ClientRefusal on failure;
 * by then the artifacts gathered so far have already been reported.
 */
export async function performAction(
  session: LabSession,
  req: ActionRequest,
  privateKey: CryptoKey,
  onStage: (stage: FlowStage, a: FlowArtifacts) => void = () => {},
): Promise<FlowArtifacts> {
  const a: FlowArtifacts = { request: req, timings: {} };
  const timed = async <T>(stage: FlowStage, fn: () => Promise<T> | T): Promise<T> => {
    const t0 = performance.now();
    const out = await fn();
    a.timings[stage] = Math.round(performance.now() - t0);
    return out;
  };

  a.challenge = await timed("challenge", () => issueChallenge(session, req));
  onStage("challenge", a);
  a.message = await timed("check", () => signedMessageFor(req, a.challenge!));
  onStage("check", a);
  a.signature = await timed("sign", () => signMessage(privateKey, a.message!));
  onStage("sign", a);
  a.decision = await timed("verify", () =>
    authenticate(session, { challengeId: a.challenge!.challenge_id, keyId: req.keyId, signature: a.signature! }),
  );
  onStage("verify", a);
  return a;
}

/** Resubmit an already-used signed response unchanged (replay demo). The server must refuse it. */
export async function replay(session: LabSession, a: FlowArtifacts): Promise<Decision> {
  if (!a.challenge || !a.signature) throw new ClientRefusal("NOTHING_TO_REPLAY", "No completed exchange to replay");
  return authenticate(session, { challengeId: a.challenge.challenge_id, keyId: a.request.keyId, signature: a.signature });
}

// --- Key fob press (kg-fob-v1, D-010) ---------------------------------------------------------------

export interface FobPress {
  counter: number;
  message: Uint8Array<ArrayBuffer>;
  signature: string;
  decision: FobDecision;
}

/** Reserve the next counter (persisted first), sign (counter, action) and send it. No server challenge. */
export async function performFobPress(
  session: LabSession,
  req: ActionRequest,
  privateKey: CryptoKey,
  reserve: (keyId: string) => Promise<number> = reserveFobCounter,
): Promise<FobPress> {
  const counter = await reserve(req.keyId);
  const message = encodeFobMessage({ vehicleId: req.vehicleId, keyId: req.keyId, counter, action: req.action });
  const signature = await signMessage(privateKey, message);
  const decision = await pressFob(session, { ...req, counter, signature });
  return { counter, message, signature, decision };
}

/** A passive key card asks for the opposite of the car's current, backend-reported state (D-010). */
export function cardTapAction(lockState: "locked" | "unlocked"): Action {
  return lockState === "locked" ? "unlock" : "lock";
}
