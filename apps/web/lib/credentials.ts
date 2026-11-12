// Credential types (docs/DECISIONS.md D-010). All are fictional models; none copies a real card or fob protocol.

import type { CredentialType } from "./api.ts";

export const CREDENTIALS: Record<CredentialType, { label: string; defaultName: string; summary: string; protocol: string }> = {
  phone: {
    label: "Phone key",
    defaultName: "My phone",
    summary: "You pick unlock or lock, then this browser signs a fresh server challenge.",
    protocol: "kg-auth-v1 · challenge-response",
  },
  card: {
    label: "Key card",
    defaultName: "Key card",
    summary: "Passive: a tap signs whatever challenge the reader shows and toggles the car. That's what makes relays possible.",
    protocol: "kg-auth-v1 · challenge-response (passive)",
  },
  fob: {
    label: "Key fob",
    defaultName: "Key fob",
    summary: "No server challenge: each button press signs a rising counter. The car rejects any counter it has already seen.",
    protocol: "kg-fob-v1 · rolling counter",
  },
};

export const CREDENTIAL_ORDER: CredentialType[] = ["phone", "card", "fob"];

/** Keys saved before Sprint 9 have no type; they were phones. */
export function credentialTypeOf(k: { credential_type?: CredentialType }): CredentialType {
  return k.credential_type ?? "phone";
}
