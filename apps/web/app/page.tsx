"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { DecisionPanel } from "@/components/DecisionPanel";
import { LabMeta, StartLab } from "@/components/LabBar";
import {
  ApiError,
  authenticate,
  getVehicles,
  issueChallenge,
  listKeys,
  type Action,
  type Decision,
  type DigitalKey,
  type Vehicle,
} from "@/lib/api";
import { ClientRefusal, signedMessageFor } from "@/lib/auth-flow";
import { signMessage } from "@/lib/crypto";
import { getKey, listKeysForLab } from "@/lib/keystore";
import { useLab } from "@/lib/use-lab";

function describe(e: unknown): string {
  if (e instanceof ApiError || e instanceof ClientRefusal) return `${e.code}: ${e.message}`;
  return String(e);
}

export default function GaragePage() {
  const { session, ready, start, end } = useLab();
  const [vehicle, setVehicle] = useState<Vehicle | null>(null);
  const [keys, setKeys] = useState<DigitalKey[]>([]);
  const [localKeyIds, setLocalKeyIds] = useState<Set<string>>(new Set());
  const [selectedKey, setSelectedKey] = useState<string>("");
  const [decision, setDecision] = useState<Decision | null>(null);
  const [pending, setPending] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (!session) return;
    try {
      const [vs, ks, local] = await Promise.all([getVehicles(session), listKeys(session), listKeysForLab(session.labId)]);
      setVehicle(vs[0] ?? null);
      setKeys(ks);
      setLocalKeyIds(new Set(local.map((k) => k.keyId)));
    } catch (e) {
      if (e instanceof ApiError && e.code === "LAB_NOT_FOUND") end();
      setError(describe(e));
    }
  }, [session, end]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
  }, [refresh]);

  // Keys this browser can actually use: active on the server AND holding the private key locally.
  const usable = keys.filter((k) => k.status === "active" && localKeyIds.has(k.id));
  const keyId = usable.some((k) => k.id === selectedKey) ? selectedKey : (usable[0]?.id ?? "");

  const run = async (action: Action) => {
    if (!session || !vehicle || !keyId) return;
    setPending(action);
    setError(null);
    try {
      const stored = await getKey(keyId);
      if (!stored) throw new ClientRefusal("KEY_NOT_IN_BROWSER", "Private key for this key ID is not in this browser");
      const req = { vehicleId: vehicle.id, keyId, action };
      const chl = await issueChallenge(session, req);
      const signature = await signMessage(stored.privateKey, signedMessageFor(req, chl));
      const d = await authenticate(session, { challengeId: chl.challenge_id, keyId, signature });
      setDecision(d);
      // Lock state shown on screen comes from the server's decision, then a fresh read.
      if (d.lock_state) setVehicle({ ...vehicle, lock_state: d.lock_state });
      await refresh();
    } catch (e) {
      setError(describe(e));
    } finally {
      setPending(null);
    }
  };

  const onStart = async () => {
    setBusy(true);
    setError(null);
    try {
      await start();
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Garage</h1>
        {session && <LabMeta session={session} onEnd={end} />}
      </header>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={error} />
      ) : (
        <>
          <section aria-labelledby="vehicle-heading" className="rounded-lg border border-line bg-panel p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 id="vehicle-heading" className="text-lg font-medium">
                  {vehicle?.name ?? "Loading vehicle…"}
                </h2>
                <p className="mt-1 font-mono text-xs text-muted">{vehicle?.id}</p>
              </div>
              {vehicle && (
                <p className="text-right">
                  <span
                    className={`block text-2xl font-semibold uppercase tracking-wide ${
                      vehicle.lock_state === "unlocked" ? "text-allow" : ""
                    }`}
                  >
                    {vehicle.lock_state}
                  </span>
                  <span className="font-mono text-xs text-muted">from backend</span>
                </p>
              )}
            </div>

            {usable.length === 0 ? (
              <p className="mt-6 text-sm">
                No usable key in this browser.{" "}
                <Link href="/keys" className="text-accent underline-offset-4 hover:underline">
                  Enroll a key
                </Link>{" "}
                to unlock or lock.
              </p>
            ) : (
              <div className="mt-6 flex flex-wrap items-end gap-3">
                <label className="flex flex-col gap-1 text-sm">
                  <span className="text-muted">Key</span>
                  <select
                    value={keyId}
                    onChange={(e) => setSelectedKey(e.target.value)}
                    className="rounded-md border border-line bg-bg px-3 py-2"
                  >
                    {usable.map((k) => (
                      <option key={k.id} value={k.id}>
                        {k.label} ({k.fingerprint.slice(0, 8)}…)
                      </option>
                    ))}
                  </select>
                </label>
                {(["unlock", "lock"] as const).map((action) => (
                  <button
                    key={action}
                    type="button"
                    onClick={() => run(action)}
                    disabled={pending !== null}
                    className="rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
                  >
                    {pending === action ? "Verifying…" : `Request ${action}`}
                  </button>
                ))}
              </div>
            )}
            <p className="mt-3 text-xs text-muted">
              Each request: server issues a 30-second challenge → this browser signs it with its non-extractable key → the
              server verifies and decides. A valid signature doesn&apos;t prove you&apos;re physically near the car.
            </p>
            {error && (
              <p role="alert" className="mt-4 font-mono text-xs text-deny">
                {error}
              </p>
            )}
          </section>

          {decision ? (
            <DecisionPanel decision={decision} />
          ) : (
            <p className="text-sm text-muted">No decision yet in this session.</p>
          )}
        </>
      )}
    </div>
  );
}
