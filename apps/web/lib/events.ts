// Pure helpers for the Security Analytics page (unit-tested in tests/events.test.ts).

import type { EventCategory } from "./api.ts";

export interface EventQuery {
  category?: EventCategory | "";
  result?: "pass" | "fail" | "";
  reason?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

export const PAGE_SIZE = 25;
export const MAX_SEARCH_LENGTH = 64; // mirrors the API's validation

/** Build the events query string. Empty filters are dropped; search text is trimmed and length-capped. */
export function eventQueryString(query: EventQuery): string {
  const params = new URLSearchParams();
  if (query.category) params.set("category", query.category);
  if (query.result) params.set("result", query.result);
  if (query.reason) params.set("reason", query.reason);
  const q = query.q?.trim().slice(0, MAX_SEARCH_LENGTH);
  if (q) params.set("q", q);
  params.set("limit", String(query.limit ?? PAGE_SIZE));
  if (query.offset) params.set("offset", String(query.offset));
  return `?${params.toString()}`;
}

/** Plain-language explanation of each failure reason code the backend can record. */
export const REASON_COPY: Record<string, string> = {
  CHALLENGE_NOT_FOUND: "No such challenge in this lab (or it was cleaned up)",
  CHALLENGE_CONSUMED: "Challenge already used: replay blocked",
  CHALLENGE_EXPIRED: "Challenge older than 30 seconds",
  KEY_MISMATCH: "Response signed for a different key than the challenge",
  KEY_UNKNOWN: "Key isn't enrolled in this lab",
  KEY_REVOKED: "Key has been revoked",
  VEHICLE_MISMATCH: "Key isn't bound to this vehicle",
  SIGNATURE_INVALID: "Signature didn't verify over the expected bytes",
  SIGNATURE_MALFORMED: "Signature isn't a valid 64-byte P-256 value",
  CHALLENGE_LIMIT_REACHED: "Too many open challenges in this lab",
  KEY_ALREADY_ENROLLED: "Public key already enrolled",
  KEY_LIMIT_REACHED: "Lab key limit reached",
  PUBLIC_KEY_INVALID: "Public key isn't valid SPKI",
  PUBLIC_KEY_UNSUPPORTED: "Only P-256 public keys are supported",
  COUNTER_REPLAYED: "Fob counter already used: replay blocked",
  COUNTER_OUT_OF_WINDOW: "Fob counter too far ahead of the last accepted one",
  COUNTER_INVALID: "Fob counter isn't a valid number",
  KEY_TYPE_MISMATCH: "Wrong protocol for this credential type",
};

export function describeReason(code: string): string {
  return REASON_COPY[code] ?? code;
}

/** Human label for an event type such as `authenticate_unlock` or `scenario_replay`. */
export function eventLabel(eventType: string): string {
  const [head, ...rest] = eventType.split("_");
  const tail = rest.join(" ");
  switch (head) {
    case "authenticate":
      return tail ? `Authenticate · ${tail}` : "Authenticate";
    case "challenge":
      return `Challenge · ${tail}`;
    case "key":
      return `Key ${tail}`;
    case "scenario":
      return `Scenario · ${tail}`;
    case "fob":
      return `Fob press · ${tail}`;
    default:
      return eventType;
  }
}

/** Share of `part` in `whole` as a whole-number percentage; 0 when there is nothing to divide. */
export function percent(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}
