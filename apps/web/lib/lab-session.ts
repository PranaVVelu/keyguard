// Lab session storage (D-002 / O-3): the bearer token lives in sessionStorage and is
// cleared when the tab closes. This is an accepted limitation for an educational demo, not a production session design.

const STORAGE_KEY = "keyguard.lab";

export interface LabSession {
  labId: string;
  labToken: string;
  expiresAt: number; // Unix seconds, from the server
}

export function loadSession(): LabSession | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as LabSession;
    if (typeof s.labId !== "string" || typeof s.labToken !== "string" || typeof s.expiresAt !== "number") return null;
    if (s.expiresAt <= Date.now() / 1000) {
      sessionStorage.removeItem(STORAGE_KEY);
      return null;
    }
    return s;
  } catch {
    return null;
  }
}

export function saveSession(s: LabSession): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s));
}

export function clearSession(): void {
  sessionStorage.removeItem(STORAGE_KEY);
}
