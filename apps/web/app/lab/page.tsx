"use client";

import { useCallback, useEffect, useState } from "react";

import { LabMeta, StartLab } from "@/components/LabBar";
import {
  ApiError,
  listLabRuns,
  listScenarios,
  runScenario,
  type LabRun,
  type ScenarioModeRun,
  type ScenarioResult,
  type ScenarioSummary,
} from "@/lib/api";
import { useLab } from "@/lib/use-lab";

const MODE_TITLE = {
  vulnerable: "Vulnerable verifier",
  hardened: "Hardened verifier",
} as const;

function describe(e: unknown) {
  return e instanceof ApiError ? `${e.code}: ${e.message}` : String(e);
}

function ModeColumn({ run, result }: { run: ScenarioModeRun; result: ScenarioResult }) {
  const expected = result.expected[run.mode];
  const accepted = run.attack_decision === "allow";
  const asExpected = run.attack_decision === expected;
  const attack = result.attack_label.toUpperCase();
  return (
    <section aria-label={MODE_TITLE[run.mode]} className="rounded-lg border border-line bg-panel p-5">
      <header className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-medium">{MODE_TITLE[run.mode]}</h3>
          <p className="mt-0.5 text-xs text-muted">{result.mode_notes[run.mode]}</p>
        </div>
        <span className="rounded-full border border-line px-2 py-0.5 font-mono text-xs uppercase">{run.mode}</span>
      </header>

      <ol className="mt-4 space-y-2">
        {run.steps.map((s) => (
          <li key={s.n} className="text-sm">
            <span className="font-mono text-xs text-muted">{String(s.n).padStart(2, "0")} / </span>
            <span className={s.actor === "attacker" ? "font-medium" : ""}>{s.label}</span>
            <div className="ml-10 font-mono text-xs">
              <span className={s.decision === "allow" ? "text-allow" : "text-deny"}>
                {s.decision.toUpperCase()}
                {s.reason ? ` · ${s.reason}` : ""}
              </span>
              <span className="text-muted"> → car {s.lock_state}</span>
            </div>
          </li>
        ))}
      </ol>

      <p className={`mt-5 border-t border-line pt-4 text-sm font-semibold ${accepted ? "text-deny" : "text-allow"}`}>
        {accepted
          ? `${attack} ACCEPTED: car is ${run.final_lock_state?.toUpperCase()}`
          : `${attack} REJECTED · ${run.attack_reason}: car stays ${run.final_lock_state?.toUpperCase()}`}
      </p>
      <p className="mt-1 font-mono text-xs text-muted">
        expected {expected} · observed {run.attack_decision} · {asExpected ? "as expected" : "UNEXPECTED"}
      </p>
    </section>
  );
}

export default function AttackLabPage() {
  const { session, ready, start, end, lost, notice } = useLab();
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([]);
  const [result, setResult] = useState<ScenarioResult | null>(null);
  const [history, setHistory] = useState<LabRun[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!session) return;
    try {
      const [sc, runs] = await Promise.all([listScenarios(session), listLabRuns(session)]);
      setScenarios(sc);
      setHistory(runs);
    } catch (e) {
      if (e instanceof ApiError && e.code === "LAB_NOT_FOUND") return lost();
      setError(describe(e));
    }
  }, [session, lost]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
  }, [refresh]);

  const onRun = async (id: string) => {
    if (!session) return;
    setRunning(id);
    setError(null);
    try {
      setResult(await runScenario(session, id));
      await refresh();
    } catch (e) {
      setError(describe(e));
    } finally {
      setRunning(null);
    }
  };

  const onStart = async () => {
    setBusy(true);
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
        <h1 className="text-3xl font-semibold tracking-tight">Attack Lab</h1>
        {session && <LabMeta session={session} onEnd={end} />}
      </header>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={error} notice={notice} />
      ) : (
        <>
          <p className="max-w-prose text-sm text-muted">
            Predefined scenarios run on <strong className="text-fg">disposable, separate state</strong>. Your lab&apos;s car and
            keys are not touched. The vulnerable verifier is isolated code that the real authentication path can&apos;t
            import (enforced by tests).
          </p>

          <ul className="grid gap-4 sm:grid-cols-2">
            {scenarios.map((s, i) => (
              <li key={s.id} className="flex flex-col rounded-lg border border-line bg-panel p-5">
                <p className="font-mono text-xs text-muted">
                  {String(i + 1).padStart(2, "0")} / {String(scenarios.length).padStart(2, "0")}
                </p>
                <h2 className="mt-1 text-lg font-medium">{s.title}</h2>
                <p className="mt-2 flex-1 text-sm text-muted">{s.description}</p>
                <div className="mt-4 flex items-center justify-between gap-3 border-t border-line pt-3 font-mono text-xs text-muted">
                  <span>expected: vulnerable {s.expected.vulnerable} · hardened {s.expected.hardened}</span>
                  <button
                    type="button"
                    onClick={() => onRun(s.id)}
                    disabled={running !== null}
                    aria-label={`Run scenario: ${s.title}`}
                    className="rounded-md bg-fg px-3 py-1.5 font-sans text-sm font-medium text-bg disabled:opacity-60"
                  >
                    {running === s.id ? "Running…" : "Run scenario"}
                  </button>
                </div>
              </li>
            ))}
          </ul>

          {result && (
            <section aria-live="polite" aria-labelledby="result-heading" className="space-y-4">
              <div className="flex flex-wrap items-baseline justify-between gap-3">
                <h2 id="result-heading" className="text-lg font-medium">
                  {result.title}:{" "}
                  <span className={result.matches_expected ? "text-allow" : "text-deny"}>
                    {result.matches_expected ? "results match expectations" : "UNEXPECTED RESULT"}
                  </span>
                </h2>
                <p className="font-mono text-xs text-muted">
                  {result.run_id} · {result.duration_ms} ms
                </p>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                {result.runs.map((r) => (
                  <ModeColumn key={r.mode} run={r} result={result} />
                ))}
              </div>
              <p className="max-w-prose text-xs text-muted">{result.takeaway}</p>
            </section>
          )}

          <section aria-labelledby="history-heading">
            <h2 id="history-heading" className="mb-2 text-lg font-medium">
              Run history <span className="font-mono text-xs text-muted">({history.length}, from backend)</span>
            </h2>
            {history.length === 0 ? (
              <p className="text-sm text-muted">No runs yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="text-muted">
                    <tr>
                      <th className="py-1 pr-4 font-normal">time</th>
                      <th className="py-1 pr-4 font-normal">scenario</th>
                      <th className="py-1 pr-4 font-normal">mode</th>
                      <th className="py-1 pr-4 font-normal">expected</th>
                      <th className="py-1 pr-4 font-normal">actual</th>
                      <th className="py-1 font-normal">match</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((r) => (
                      <tr key={`${r.run_id}-${r.mode}`} className="border-t border-line">
                        <td className="py-1 pr-4">{new Date(r.created_at * 1000).toLocaleTimeString()}</td>
                        <td className="py-1 pr-4">{r.scenario}</td>
                        <td className="py-1 pr-4">{r.mode}</td>
                        <td className="py-1 pr-4">{r.expected_result}</td>
                        <td className="py-1 pr-4">
                          {r.actual_result}
                          {r.actual_reason ? ` · ${r.actual_reason}` : ""}
                        </td>
                        <td className="py-1">{r.expected_result === r.actual_result ? "yes" : "NO"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
