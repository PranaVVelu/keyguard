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

export type CredentialType = "phone" | "card" | "fob";

export interface DigitalKey {
  id: string;
  vehicle_id: string;
  label: string;
  fingerprint: string;
  status: "active" | "revoked";
  credential_type: CredentialType;
  last_counter: number; // kg-fob-v1 only
  created_at: number;
  revoked_at: number | null;
}

async function request<T>(
  path: string,
  init: RequestInit & { session?: LabSession; account?: boolean } = {},
): Promise<T> {
  const { session, account, ...rest } = init;
  const headers = new Headers(rest.headers);
  if (session) headers.set("Authorization", `Bearer ${session.labToken}`);
  if (rest.body) headers.set("Content-Type", "application/json");
  // Account calls carry the HttpOnly session cookie and the CSRF header the API requires (D-012).
  if (account) headers.set("X-KeyGuard-CSRF", "1");

  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}${path}`, { ...rest, headers, ...(account ? { credentials: "include" as const } : {}) });
  } catch {
    throw new ApiError(0, "NETWORK_ERROR", `Could not reach the API at ${API_BASE}`);
  }
  if (resp.status === 204) return undefined as T;
  const body = await resp.json().catch(() => null);
  if (!resp.ok) {
    const err = body?.error;
    let message: string = err?.message ?? `HTTP ${resp.status}`;
    const retry = resp.headers.get("Retry-After");
    if (resp.status === 429 && retry && /^\d+$/.test(retry)) message += `; try again in ${retry} s`;
    throw new ApiError(resp.status, err?.code ?? "HTTP_ERROR", message);
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
  input: { vehicleId: string; publicKey: string; label: string; credentialType?: CredentialType },
): Promise<DigitalKey> {
  return request<DigitalKey>(`/api/labs/${session.labId}/keys`, {
    method: "POST",
    session,
    body: JSON.stringify({
      vehicle_id: input.vehicleId,
      public_key: input.publicKey,
      label: input.label,
      credential_type: input.credentialType ?? "phone",
    }),
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

export async function revokeKey(session: LabSession, keyId: string): Promise<DigitalKey> {
  return request<DigitalKey>(`/api/labs/${session.labId}/keys/${encodeURIComponent(keyId)}/revoke`, {
    method: "POST",
    session,
  });
}

export type LabMode = "vulnerable" | "hardened";

export interface ScenarioStep {
  n: number;
  actor: "owner" | "attacker";
  label: string;
  decision: "allow" | "deny";
  reason: string | null;
  lock_state: "locked" | "unlocked" | null;
}

export interface ScenarioModeRun {
  mode: LabMode;
  steps: ScenarioStep[];
  final_lock_state: "locked" | "unlocked" | null;
  attack_decision: "allow" | "deny";
  attack_reason: string | null;
}

export interface ScenarioSummary {
  id: string;
  title: string;
  description: string;
  expected: Record<LabMode, "allow" | "deny">;
  /** What the attacker submits, e.g. "Replay" or "Tampered response" (used in the outcome line). */
  attack_label: string;
  /** What each verifier does, in this scenario's terms. */
  mode_notes: Record<LabMode, string>;
  /** The lesson shown under a result. */
  takeaway: string;
}

export interface ScenarioResult extends ScenarioSummary {
  run_id: string;
  scenario: string;
  actual: Record<LabMode, "allow" | "deny">;
  matches_expected: boolean;
  runs: ScenarioModeRun[];
  duration_ms: number;
  created_at: number;
}

export interface LabRun {
  run_id: string;
  scenario: string;
  mode: LabMode;
  expected_result: string;
  actual_result: string;
  actual_reason: string | null;
  duration_ms: number | null;
  created_at: number;
}

export async function listScenarios(session: LabSession): Promise<ScenarioSummary[]> {
  return (await request<{ scenarios: ScenarioSummary[] }>(`/api/labs/${session.labId}/scenarios`, { session })).scenarios;
}

export async function runScenario(session: LabSession, scenario: string): Promise<ScenarioResult> {
  return request<ScenarioResult>(`/api/labs/${session.labId}/scenarios/${encodeURIComponent(scenario)}`, {
    method: "POST",
    session,
  });
}

export async function listLabRuns(session: LabSession): Promise<LabRun[]> {
  return (await request<{ runs: LabRun[] }>(`/api/labs/${session.labId}/lab-runs`, { session })).runs;
}

export type EventCategory = "authentication" | "challenge" | "key" | "scenario";

export interface SecurityEvent {
  id: string;
  event_type: string;
  category: EventCategory | "other";
  outcome: string;
  result: "pass" | "fail";
  reason: string | null;
  vehicle_id: string | null;
  key_id: string | null;
  duration_ms: number | null;
  created_at: number;
}

export interface EventPage {
  total: number;
  limit: number;
  offset: number;
  events: SecurityEvent[];
}

export interface EventSummary {
  total: number;
  pass: number;
  fail: number;
  by_category: Record<EventCategory, { pass: number; fail: number }>;
  failure_reasons: { reason: string; count: number }[];
  authentication: { allowed: number; denied: number; median_ms: number | null; p95_ms: number | null };
}

export async function listEvents(session: LabSession, query: string): Promise<EventPage> {
  return request<EventPage>(`/api/labs/${session.labId}/events${query}`, { session });
}

export async function getEventSummary(session: LabSession): Promise<EventSummary> {
  return request<EventSummary>(`/api/labs/${session.labId}/events/summary`, { session });
}

// --- Key fob (kg-fob-v1, D-010) ---------------------------------------------------------------------

export interface FobDecision {
  decision: "allow" | "deny";
  reason: string | null;
  key_id: string;
  vehicle_id: string | null;
  action: Action;
  counter: number;
  last_counter: number | null;
  lock_state: "locked" | "unlocked" | null;
  duration_ms: number;
  trace: TraceStep[];
}

export async function pressFob(
  session: LabSession,
  input: { vehicleId: string; keyId: string; action: Action; counter: number; signature: string },
): Promise<FobDecision> {
  return request<FobDecision>(`/api/labs/${session.labId}/fob`, {
    method: "POST",
    session,
    body: JSON.stringify({
      vehicle_id: input.vehicleId,
      key_id: input.keyId,
      action: input.action,
      counter: input.counter,
      signature: input.signature,
    }),
  });
}

// --- Accounts, passkeys and saved labs (F12, D-012) -----------------------------------------------

export interface SavedLab {
  lab_id: string;
  saved_at: number | null;
  expires_at: number;
  vehicle_name: string;
  lock_state: string;
  event_count: number;
}

export interface AccountSummary {
  account: { id: string; display_name: string; created_at: number };
  passkeys: { id_prefix: string; created_at: number; last_used_at: number | null }[];
  saved_labs: SavedLab[];
}

export interface WebAuthnOptions {
  challenge_id: string;
  options: Record<string, unknown>;
}

/** The signed-in account, or null when there's no valid session. */
export async function getAccount(): Promise<AccountSummary | null> {
  try {
    return await request<AccountSummary>("/api/account", { account: true });
  } catch (e) {
    if (e instanceof ApiError && e.code === "NOT_SIGNED_IN") return null;
    throw e;
  }
}

export function registerOptions(displayName: string): Promise<WebAuthnOptions> {
  return request("/api/auth/register/options", { method: "POST", account: true, body: JSON.stringify({ display_name: displayName }) });
}

export function registerVerify(challengeId: string, credential: unknown): Promise<AccountSummary> {
  return request("/api/auth/register/verify", {
    method: "POST", account: true, body: JSON.stringify({ challenge_id: challengeId, credential }),
  });
}

export function loginOptions(): Promise<WebAuthnOptions> {
  return request("/api/auth/login/options", { method: "POST", account: true });
}

export function loginVerify(challengeId: string, credential: unknown): Promise<AccountSummary> {
  return request("/api/auth/login/verify", {
    method: "POST", account: true, body: JSON.stringify({ challenge_id: challengeId, credential }),
  });
}

export function logout(): Promise<void> {
  return request("/api/auth/logout", { method: "POST", account: true });
}

export function deleteAccount(): Promise<void> {
  return request("/api/account/delete", { method: "POST", account: true, body: JSON.stringify({ confirm: "DELETE" }) });
}

export function saveLab(session: LabSession): Promise<AccountSummary> {
  return request(`/api/labs/${session.labId}/save`, { method: "POST", account: true, session });
}

export async function openSavedLab(labId: string): Promise<LabSession> {
  const r = await request<{ lab_id: string; lab_token: string; expires_at: number }>(
    `/api/account/labs/${encodeURIComponent(labId)}/open`,
    { method: "POST", account: true },
  );
  return { labId: r.lab_id, labToken: r.lab_token, expiresAt: r.expires_at };
}

export function unsaveLab(labId: string): Promise<AccountSummary> {
  return request(`/api/account/labs/${encodeURIComponent(labId)}/unsave`, { method: "POST", account: true });
}
