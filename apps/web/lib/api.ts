// Typed client for the KeyGuard API. The UI renders only what these calls return.

import type { LabSession } from "./lab-session.ts";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface Vehicle {
  id: string;
  name: string;
  lock_state: "locked" | "unlocked";
}

export interface DigitalKey {
  id: string;
  vehicle_id: string;
  label: string;
  fingerprint: string;
  status: "active" | "revoked";
  created_at: number;
  revoked_at: number | null;
}

async function request<T>(path: string, init: RequestInit & { session?: LabSession } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.session) headers.set("Authorization", `Bearer ${init.session.labToken}`);
  if (init.body) headers.set("Content-Type", "application/json");

  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "NETWORK_ERROR", `Could not reach the API at ${API_BASE}`);
  }
  const body = await resp.json().catch(() => null);
  if (!resp.ok) {
    const err = body?.error;
    throw new ApiError(resp.status, err?.code ?? "HTTP_ERROR", err?.message ?? `HTTP ${resp.status}`);
  }
  return body as T;
}

export async function createLab(): Promise<LabSession> {
  const r = await request<{ lab_id: string; lab_token: string; expires_at: number }>("/api/labs", { method: "POST" });
  return { labId: r.lab_id, labToken: r.lab_token, expiresAt: r.expires_at };
}

export async function getVehicles(session: LabSession): Promise<Vehicle[]> {
  return (await request<{ vehicles: Vehicle[] }>(`/api/labs/${session.labId}/vehicles`, { session })).vehicles;
}

export async function listKeys(session: LabSession): Promise<DigitalKey[]> {
  return (await request<{ keys: DigitalKey[] }>(`/api/labs/${session.labId}/keys`, { session })).keys;
}

export async function enrollKey(
  session: LabSession,
  input: { vehicleId: string; publicKey: string; label: string },
): Promise<DigitalKey> {
  return request<DigitalKey>(`/api/labs/${session.labId}/keys`, {
    method: "POST",
    session,
    body: JSON.stringify({ vehicle_id: input.vehicleId, public_key: input.publicKey, label: input.label }),
  });
}

export type Action = "unlock" | "lock";

export interface Challenge {
  protocol_version: "kg-auth-v1";
  challenge_id: string;
  vehicle_id: string;
  key_id: string;
  nonce: string;
  action: Action;
  expires_at: number;
}

export interface TraceStep {
  step: string;
  status: "pass" | "fail" | "skipped";
  detail: string | null;
}

export interface Decision {
  decision: "allow" | "deny";
  reason: string | null;
  challenge_id: string;
  vehicle_id: string | null;
  action: Action | null;
  lock_state: "locked" | "unlocked" | null;
  duration_ms: number;
  trace: TraceStep[];
}

export async function issueChallenge(
  session: LabSession,
  input: { vehicleId: string; keyId: string; action: Action },
): Promise<Challenge> {
  return request<Challenge>(`/api/labs/${session.labId}/challenges`, {
    method: "POST",
    session,
    body: JSON.stringify({ vehicle_id: input.vehicleId, key_id: input.keyId, action: input.action }),
  });
}

export async function authenticate(
  session: LabSession,
  input: { challengeId: string; keyId: string; signature: string },
): Promise<Decision> {
  return request<Decision>(`/api/labs/${session.labId}/authenticate`, {
    method: "POST",
    session,
    body: JSON.stringify({ challenge_id: input.challengeId, key_id: input.keyId, signature: input.signature }),
  });
}
