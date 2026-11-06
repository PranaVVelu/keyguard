// Sprint 1 placeholder data. Nothing here comes from the backend, and the UI labels it as mock.
// Replace with lib/api.ts calls once authentication is wired up (Sprint 3).

export type LockState = "locked" | "unlocked";

export interface MockGarage {
  vehicle: { name: string; lockState: LockState };
  keys: { label: string; status: "active" | "revoked" }[];
  latestEvent: string | null;
}

export const MOCK_GARAGE: MockGarage = {
  vehicle: { name: "KG Coupe (fictional)", lockState: "locked" },
  keys: [],
  latestEvent: null,
};
