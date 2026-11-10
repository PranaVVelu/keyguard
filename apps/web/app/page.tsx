"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { DecisionPanel } from "@/components/DecisionPanel";
import { LabMeta, StartLab } from "@/components/LabBar";
import { VehicleVisual } from "@/components/VehicleVisual";
import { ApiError, listEvents, type Action, type Decision, type SecurityEvent } from "@/lib/api";
import { ClientRefusal, performAction } from "@/lib/auth-flow";
import { describeReason, eventLabel, eventQueryString } from "@/lib/events";
import { getKey } from "@/lib/keystore";
import { useLab } from "@/lib/use-lab";
import { useLabKeys } from "@/lib/use-keys";

function describe(e: unknown): string {
  if (e instanceof ApiError || e instanceof ClientRefusal) return `${e.code}: ${e.message}`;
  return String(e);
}

export default function GaragePage() {
  const { session, ready, start, end, lost, notice } = useLab();
  const { vehicle, setVehicle, usable, error: loadError, refresh } = useLabKeys(session, lost);
  const [selectedKey, setSelectedKey] = useState<string>("");
  const [decision, setDecision] = useState<Decision | null>(null);
  const [pending, setPending] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [latest, setLatest] = useState<SecurityEvent | null>(null);

  const loadLatest = useCallback(async () => {
    if (!session) return;
    try {
      setLatest((await listEvents(session, eventQueryString({ limit: 1 }))).events[0] ?? null);
    } catch {
      // Non-essential: the decision panel already shows the outcome.
    }
  }, [session]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void loadLatest();
  }, [loadLatest]);

  const keyId = usable.some((k) => k.id === selectedKey) ? selectedKey : (usable[0]?.id ?? "");

  const run = async (action: Action) => {
    if (!session || !vehicle || !keyId) return;
    setPending(action);
    setError(null);
    try {
      const stored = await getKey(keyId);
      if (!stored) throw new ClientRefusal("KEY_NOT_IN_BROWSER", "Private key for this key ID is not in this browser");
      const { decision: d } = await performAction(session, { vehicleId: vehicle.id, keyId, action }, stored.privateKey);
      setDecision(d!);
      // Lock state shown on screen comes from the server's decision, then a fresh read.
      if (d?.lock_state) setVehicle({ ...vehicle, lock_state: d.lock_state });
      await refresh();
    } catch (e) {
      setError(describe(e));
    } finally {
      setPending(null);
      void loadLatest();
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

  const shownError = error ?? loadError;

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Garage</h1>
        {session && <LabMeta session={session} onEnd={end} />}
      </header>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={shownError} notice={notice} />
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
                <p className="text-right" aria-live="polite">
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

            <div className="my-6 flex justify-center">
              <VehicleVisual lockState={vehicle?.lock_state} />
            </div>

            {usable.length === 0 ? (
              <p className="text-sm">
                No usable key in this browser.{" "}
                <Link href="/keys" className="text-accent underline underline-offset-4">
                  Enroll a key
                </Link>{" "}
                to unlock or lock.
              </p>
            ) : (
              <div className="flex flex-wrap items-end gap-3">
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
                <Link href="/inspector" className="ml-auto text-sm text-accent underline-offset-4 hover:underline">
                  Step through it in the Inspector →
                </Link>
              </div>
            )}
            <p className="mt-3 text-xs text-muted">
              Each request: server issues a 30-second challenge → this browser signs it with its non-extractable key → the
              server verifies and decides. The car graphic only mirrors the backend&apos;s answer. A valid signature
              doesn&apos;t prove you&apos;re physically near the car.
            </p>
            {latest && (
              <p className="mt-4 border-t border-line pt-3 text-xs text-muted">
                Latest event:{" "}
                <span className="text-fg">{eventLabel(latest.event_type)}</span>{" "}
                <span className={`font-mono uppercase ${latest.result === "pass" ? "text-allow" : "text-deny"}`}>
                  {latest.outcome.replace("_", " ")}
                </span>
                {latest.reason && <span> · {describeReason(latest.reason)}</span>}{" "}
                <span className="font-mono">· {new Date(latest.created_at * 1000).toLocaleTimeString()}</span>{" "}
                <Link href="/analytics" className="text-accent underline underline-offset-4">
                  All events →
                </Link>
              </p>
            )}
            {shownError && (
              <p role="alert" className="mt-4 font-mono text-xs text-deny">
                {shownError}
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
