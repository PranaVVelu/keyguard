"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, getVehicles, listKeys, type DigitalKey, type Vehicle } from "./api.ts";
import { listKeysForLab } from "./keystore.ts";
import type { LabSession } from "./lab-session.ts";

/**
 * Vehicle and keys for the current lab. `usable` = active on the server AND private key present in this browser.
 * Calls `onLabGone` if the server no longer recognises the lab.
 */
export function useLabKeys(session: LabSession | null, onLabGone: () => void) {
  const [vehicle, setVehicle] = useState<Vehicle | null>(null);
  const [keys, setKeys] = useState<DigitalKey[]>([]);
  const [localIds, setLocalIds] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!session) return;
    try {
      const [vs, ks, local] = await Promise.all([getVehicles(session), listKeys(session), listKeysForLab(session.labId)]);
      setVehicle(vs[0] ?? null);
      setKeys(ks);
      setLocalIds(new Set(local.map((k) => k.keyId)));
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.code === "LAB_NOT_FOUND") onLabGone();
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    }
  }, [session, onLabGone]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
  }, [refresh]);

  const usable = keys.filter((k) => k.status === "active" && localIds.has(k.id));
  return { vehicle, setVehicle, keys, usable, error, refresh };
}
