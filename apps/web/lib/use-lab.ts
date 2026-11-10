"use client";

import { useCallback, useEffect, useState } from "react";

import { createLab } from "./api.ts";
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
    await purgeOtherLabs(s.labId).catch(() => undefined);
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

  return { session, ready, start, end, lost, notice };
}
