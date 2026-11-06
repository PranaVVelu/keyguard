"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { LabMeta, StartLab } from "@/components/LabBar";
import { ApiError, getVehicles, listKeys, type DigitalKey, type Vehicle } from "@/lib/api";
import { useLab } from "@/lib/use-lab";

export default function GaragePage() {
  const { session, ready, start, end } = useLab();
  const [vehicle, setVehicle] = useState<Vehicle | null>(null);
  const [keys, setKeys] = useState<DigitalKey[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    Promise.all([getVehicles(session), listKeys(session)])
      .then(([vs, ks]) => {
        if (cancelled) return;
        setVehicle(vs[0] ?? null);
        setKeys(ks);
        setError(null);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && e.code === "LAB_NOT_FOUND") end();
        setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [session, end]);

  const onStart = async () => {
    setBusy(true);
    setError(null);
    try {
      await start();
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  const activeKeys = keys.filter((k) => k.status === "active").length;

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Garage</h1>
        {session && <LabMeta session={session} onEnd={end} />}
      </header>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={error} />
      ) : (
        <section aria-labelledby="vehicle-heading" className="rounded-lg border border-line bg-panel p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 id="vehicle-heading" className="text-lg font-medium">
                {vehicle?.name ?? "Loading vehicle…"}
              </h2>
              <p className="mt-1 font-mono text-xs text-muted">{vehicle?.id}</p>
            </div>
            {vehicle && (
              <p className="text-sm">
                Lock state: <span className="font-semibold uppercase">{vehicle.lock_state}</span>{" "}
                <span className="font-mono text-xs text-muted">(from backend)</span>
              </p>
            )}
          </div>

          <dl className="mt-6 grid gap-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-muted">Digital keys</dt>
              <dd>
                {activeKeys} active{" "}
                <Link href="/keys" className="text-accent underline-offset-4 hover:underline">
                  Manage keys
                </Link>
              </dd>
            </div>
            <div>
              <dt className="text-muted">Latest decision</dt>
              <dd>None yet: no authentication has run</dd>
            </div>
          </dl>

          <div className="mt-6 flex flex-wrap gap-3">
            {(["Request unlock", "Request lock"] as const).map((label) => (
              <button
                key={label}
                type="button"
                disabled
                aria-describedby="actions-note"
                className="rounded-md border border-line px-4 py-2 text-sm text-muted disabled:cursor-not-allowed"
              >
                {label}
              </button>
            ))}
          </div>
          <p id="actions-note" className="mt-2 text-xs text-muted">
            Unlock and lock arrive in Sprint 3 (challenge, signature, server verification). Until then, lock state can&apos;t change.
          </p>
          {error && (
            <p role="alert" className="mt-4 font-mono text-xs text-deny">
              {error}
            </p>
          )}
        </section>
      )}
    </div>
  );
}
