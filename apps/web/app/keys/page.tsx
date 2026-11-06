"use client";

import { useCallback, useEffect, useState } from "react";

import { LabMeta, StartLab } from "@/components/LabBar";
import { ApiError, enrollKey, getVehicles, listKeys, type DigitalKey, type Vehicle } from "@/lib/api";
import { exportPublicKey, generateDeviceKey, publicKeyFingerprint } from "@/lib/crypto";
import { listKeysForLab, saveKey } from "@/lib/keystore";
import { useLab } from "@/lib/use-lab";

type Step = { label: string; detail?: string; state: "done" | "failed" };

export default function KeysPage() {
  const { session, ready, start, end } = useLab();
  const [vehicle, setVehicle] = useState<Vehicle | null>(null);
  const [keys, setKeys] = useState<DigitalKey[]>([]);
  const [localKeyIds, setLocalKeyIds] = useState<Set<string>>(new Set());
  const [label, setLabel] = useState("My phone");
  const [steps, setSteps] = useState<Step[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!session) return;
    try {
      const [vs, ks, local] = await Promise.all([getVehicles(session), listKeys(session), listKeysForLab(session.labId)]);
      setVehicle(vs[0] ?? null);
      setKeys(ks);
      setLocalKeyIds(new Set(local.map((k) => k.keyId)));
    } catch (e) {
      if (e instanceof ApiError && e.code === "LAB_NOT_FOUND") end();
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    }
  }, [session, end]);

  useEffect(() => {
    // Loading server state into React state is what this effect is for.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
  }, [refresh]);

  const onEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!session || !vehicle) return;
    setBusy(true);
    setError(null);
    const log: Step[] = [];
    const push = (s: Step) => {
      log.push(s);
      setSteps([...log]);
    };
    try {
      const pair = await generateDeviceKey();
      push({ label: "Generated P-256 key pair in this browser", detail: "private key: non-extractable", state: "done" });

      const spki = await exportPublicKey(pair.publicKey);
      const localFp = await publicKeyFingerprint(spki);
      push({ label: "Exported public key only (SPKI)", detail: `sha256 ${localFp}`, state: "done" });

      const enrolled = await enrollKey(session, { vehicleId: vehicle.id, publicKey: spki, label: label.trim() });
      const match = enrolled.fingerprint === localFp;
      push({
        label: match ? "Server accepted and stored the public key" : "Server fingerprint mismatch",
        detail: `${enrolled.id} · server sha256 ${enrolled.fingerprint}`,
        state: match ? "done" : "failed",
      });
      if (!match) return;

      await saveKey({
        keyId: enrolled.id,
        labId: session.labId,
        privateKey: pair.privateKey,
        fingerprint: localFp,
        createdAt: enrolled.created_at,
      });
      push({ label: "Saved private key handle to IndexedDB", detail: "survives refresh; bytes not readable", state: "done" });
      await refresh();
    } catch (err) {
      const msg = err instanceof ApiError ? `${err.code}: ${err.message}` : String(err);
      push({ label: "Enrollment failed: key discarded", detail: msg, state: "failed" });
      setError(msg);
    } finally {
      setBusy(false);
    }
  };

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

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Digital Keys</h1>
        {session && <LabMeta session={session} onEnd={end} />}
      </header>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={error} />
      ) : (
        <>
          <section aria-labelledby="enroll-heading" className="rounded-lg border border-line bg-panel p-6">
            <h2 id="enroll-heading" className="text-lg font-medium">
              Enroll a new key
            </h2>
            <p className="mt-1 max-w-prose text-sm text-muted">
              Your browser generates the key pair. Only the public key is sent to the server; the private key stays here
              and can&apos;t be exported.
            </p>
            <form onSubmit={onEnroll} className="mt-4 flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Label</span>
                <input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  maxLength={40}
                  required
                  className="rounded-md border border-line bg-bg px-3 py-2"
                />
              </label>
              <p className="text-sm">
                <span className="text-muted">Vehicle </span>
                {vehicle?.name ?? "…"}
              </p>
              <button
                type="submit"
                disabled={busy || !vehicle || !label.trim()}
                className="rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
              >
                {busy ? "Enrolling…" : "Generate & enroll key"}
              </button>
            </form>

            {steps.length > 0 && (
              <ol aria-label="Enrollment steps" className="mt-5 space-y-2 border-t border-line pt-4">
                {steps.map((s, i) => (
                  <li key={i} className="text-sm">
                    <span className="font-mono text-xs text-muted">{String(i + 1).padStart(2, "0")} / </span>
                    <span className={s.state === "failed" ? "text-deny" : ""}>
                      {s.state === "failed" ? "FAILED · " : ""}
                      {s.label}
                    </span>
                    {s.detail && <div className="ml-10 break-all font-mono text-xs text-muted">{s.detail}</div>}
                  </li>
                ))}
              </ol>
            )}
          </section>

          <section aria-labelledby="keys-heading">
            <h2 id="keys-heading" className="mb-3 text-lg font-medium">
              Enrolled keys <span className="font-mono text-xs text-muted">({keys.length}, from backend)</span>
            </h2>
            {keys.length === 0 ? (
              <p className="text-sm text-muted">No keys enrolled yet.</p>
            ) : (
              <ul className="grid gap-4 sm:grid-cols-2">
                {keys.map((k) => (
                  <li key={k.id} className="rounded-lg border border-line bg-panel p-5">
                    <div className="flex items-start justify-between gap-3">
                      <p className="font-medium">{k.label}</p>
                      <span className="rounded-full border border-line px-2 py-0.5 font-mono text-xs uppercase">
                        {k.status}
                      </span>
                    </div>
                    <dl className="mt-3 space-y-1 font-mono text-xs text-muted">
                      <div>
                        <dt className="inline">id </dt>
                        <dd className="inline">{k.id}</dd>
                      </div>
                      <div className="break-all">
                        <dt className="inline">sha256 </dt>
                        <dd className="inline">{k.fingerprint}</dd>
                      </div>
                      <div>
                        <dt className="inline">enrolled </dt>
                        <dd className="inline">{new Date(k.created_at * 1000).toLocaleString()}</dd>
                      </div>
                      <div>
                        <dt className="inline">private key </dt>
                        <dd className="inline">{localKeyIds.has(k.id) ? "in this browser" : "not in this browser"}</dd>
                      </div>
                    </dl>
                    <button
                      type="button"
                      disabled
                      title="Revocation arrives in Sprint 4"
                      className="mt-4 rounded-md border border-line px-3 py-1.5 text-xs text-muted disabled:cursor-not-allowed"
                    >
                      Revoke (Sprint 4)
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          {error && (
            <p role="alert" className="font-mono text-xs text-deny">
              {error}
            </p>
          )}
        </>
      )}
    </div>
  );
}
