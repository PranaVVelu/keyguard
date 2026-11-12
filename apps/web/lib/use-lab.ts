"use client";

import { useCallback, useEffect, useState } from "react";

import { createLab, getAccount } from "./api.ts";
import { purgeOtherLabs } from "./keystore.ts";
import { clearSession, loadSession, saveSession, type LabSession } from "./lab-session.ts";

/** The current lab session, loaded from sessionStorage after mount (it is never rendered on the server). */
export function useLab() {
  const [session, setSession] = useState<LabSession | null>(null);
  const [ready, setReady] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    // sessionStorage only exists in the browser, so this must run after hydration.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSession(loadSession());
    setReady(true);
  }, []);

  const start = useCallback(async () => {
    const s = await createLab();
    saveSession(s);
    // Keep this browser's keys for labs saved to the signed-in account (D-012); drop keys for every other lab.
    const saved = await getAccount().then((a) => a?.saved_labs.map((l) => l.lab_id) ?? []).catch(() => []);
    await purgeOtherLabs(s.labId, saved).catch(() => undefined);
    setNotice(null);
    setSession(s);
    return s;
  }, []);

  const end = useCallback(() => {
    clearSession();
    setSession(null);
  }, []);

  /** The server no longer recognises this lab (expired after 24 h, or cleaned up). Explain instead of vanishing. */
  const lost = useCallback(() => {
    clearSession();
    setSession(null);
    setNotice("Your previous lab has expired or was removed, so its car, keys and history are gone. Start a new lab to continue.");
  }, []);

  /** Switch this tab to a lab opened from the account (a fresh token from the server). */
  const adopt = useCallback((s: LabSession) => {
    saveSession(s);
    setNotice(null);
    setSession(s);
  }, []);

  return { session, ready, start, end, lost, notice, adopt };
}
