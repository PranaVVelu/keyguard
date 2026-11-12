"use client";

import { useState } from "react";

import { LabMeta, StartLab } from "@/components/LabBar";
import { ApiError, runScenario, type ScenarioResult } from "@/lib/api";
import { useLab } from "@/lib/use-lab";

// D-011: everything on this page except the relay result is illustrative. The distance never leaves the browser.

const CARD_RANGE_M = 0.05; // a few centimetres, conceptual
const MAX_DISTANCE_M = 100;

function describe(e: unknown) {
  return e instanceof ApiError ? `${e.code}: ${e.message}` : String(e);
}

function Scene({ distance, relay }: { distance: number; relay: boolean }) {
  // Car on the left; the owner slides right with distance (log-ish scale so 0–5 m is readable).
  const x = 150 + Math.round((Math.log10(1 + distance) / Math.log10(1 + MAX_DISTANCE_M)) * 470);
  const inRange = distance <= CARD_RANGE_M;
  return (
    <svg viewBox="0 0 680 220" role="img" aria-labelledby="scene-title scene-desc" className="h-auto w-full">
      <title id="scene-title">Conceptual relay diagram</title>
      <desc id="scene-desc">
        {`Car with a card reader on the left. The owner and their key card are ${distance} metres away.${
          relay ? " Attacker A stands at the car and attacker B next to the owner, relaying the challenge between them." : ""
        }`}
      </desc>
      {/* ground */}
      <line x1="20" y1="180" x2="660" y2="180" stroke="var(--line)" />
      {/* car */}
      <rect x="30" y="120" width="100" height="50" rx="18" fill="var(--panel)" stroke="var(--line)" strokeWidth="2" />
      <rect x="55" y="128" width="50" height="22" rx="6" fill="var(--bg)" stroke="var(--line)" />
      <circle cx="130" cy="150" r="5" fill="var(--accent)" />
      <text x="80" y="200" textAnchor="middle" fontSize="11" fill="var(--muted)">car + reader</text>
      {/* conceptual card range */}
      <circle cx="130" cy="150" r="14" fill="none" stroke="var(--accent)" strokeDasharray="3 3" opacity="0.6" />
      {/* owner */}
      <g transform={`translate(${x} 0)`}>
        <circle cx="0" cy="118" r="10" fill="var(--panel)" stroke="var(--fg)" />
        <line x1="0" y1="128" x2="0" y2="160" stroke="var(--fg)" />
        <line x1="0" y1="160" x2="-8" y2="178" stroke="var(--fg)" />
        <line x1="0" y1="160" x2="8" y2="178" stroke="var(--fg)" />
        <rect x="6" y="138" width="12" height="8" rx="1.5" fill="var(--warn-fg)" />
        <text x="0" y="200" textAnchor="middle" fontSize="11" fill="var(--muted)">
          owner · {distance} m
        </text>
      </g>
      {relay && (
        <>
          {/* attacker A by the car, B by the owner, and the relay link */}
          <g>
            <circle cx="170" cy="118" r="9" fill="var(--panel)" stroke="var(--deny)" />
            <line x1="170" y1="127" x2="170" y2="176" stroke="var(--deny)" />
            <text x="170" y="100" textAnchor="middle" fontSize="11" fill="var(--deny)">A</text>
          </g>
          <g transform={`translate(${Math.max(200, x - 34)} 0)`}>
            <circle cx="0" cy="118" r="9" fill="var(--panel)" stroke="var(--deny)" />
            <line x1="0" y1="127" x2="0" y2="176" stroke="var(--deny)" />
            <text x="0" y="100" textAnchor="middle" fontSize="11" fill="var(--deny)">B</text>
          </g>
          <path
            d={`M170 92 Q ${(170 + Math.max(200, x - 34)) / 2} 30 ${Math.max(200, x - 34)} 92`}
            fill="none"
            stroke="var(--deny)"
            strokeDasharray="6 4"
          />
          <text x={(170 + Math.max(200, x - 34)) / 2} y="40" textAnchor="middle" fontSize="11" fill="var(--deny)">
            challenge → ← signature (relayed)
          </text>
        </>
      )}
      <text x="660" y="20" textAnchor="end" fontSize="11" fill="var(--muted)">
        {inRange ? "card at the reader" : relay ? "card reached only through the relay" : "card out of reader range"}
      </text>
    </svg>
  );
}

export default function ProximityPage() {
  const { session, ready, start, end, notice } = useLab();
  const [distance, setDistance] = useState(40);
  const [relay, setRelay] = useState(true);
  const [result, setResult] = useState<ScenarioResult | null>(null);
  const [ranAt, setRanAt] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

  const onRun = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await runScenario(session, "relay"));
      setRanAt(distance);
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">
          Proximity <span className="text-muted">(conceptual)</span>
        </h1>
        {session && <LabMeta session={session} onEnd={end} />}
      </header>

      <p role="note" className="max-w-prose rounded-md border border-line bg-warn-bg px-3 py-2 text-sm text-warn-fg">
        This page is an illustration. The distance slider and the drawing never reach the server and never change a
        decision. Only the relay result below comes from the backend.
      </p>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={error} notice={notice} />
      ) : (
        <>
          <section aria-labelledby="scene-heading" className="rounded-lg border border-line bg-panel p-5">
            <h2 id="scene-heading" className="sr-only">
              Scene
            </h2>
            <Scene distance={distance} relay={relay} />
            <div className="mt-4 flex flex-wrap items-center gap-6">
              <label className="flex flex-1 flex-col gap-1 text-sm">
                <span className="text-muted">
                  Owner&apos;s distance from the car: <span className="font-mono text-fg">{distance} m</span>
                </span>
                <input
                  type="range"
                  min={0}
                  max={MAX_DISTANCE_M}
                  step={1}
                  value={distance}
                  onChange={(e) => setDistance(Number(e.target.value))}
                  className="accent-[var(--accent)]"
                />
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={relay}
                  onChange={(e) => setRelay(e.target.checked)}
                  className="accent-[var(--accent)]"
                />
                Relay attackers present
              </label>
              <button
                type="button"
                onClick={onRun}
                disabled={busy}
                className="rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
              >
                {busy ? "Running…" : "Run the relay on the real backend"}
              </button>
            </div>
          </section>

          {error && (
            <p role="alert" className="font-mono text-xs text-deny">
              {error}
            </p>
          )}

          {result && (
            <section aria-live="polite" aria-labelledby="relay-heading" className="rounded-lg border border-line bg-panel p-5">
              <h2 id="relay-heading" className="font-medium">
                Backend result: {result.title}
              </h2>
              <ul className="mt-3 space-y-1 font-mono text-sm">
                {result.runs.map((r) => (
                  <li key={r.mode}>
                    <span className="text-muted">{r.mode === "hardened" ? "Production engine" : "Vulnerable verifier"}: </span>
                    <span className={r.attack_decision === "allow" ? "text-deny" : "text-allow"}>
                      relayed unlock {r.attack_decision === "allow" ? "ACCEPTED" : "REJECTED"}
                    </span>
                    <span className="text-muted"> → car {r.final_lock_state}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-sm">
                The slider was at <span className="font-mono">{ranAt} m</span> when you ran this. It wasn&apos;t sent, and
                the server would decide the same at 0 m or 1 km: nothing in the signed message carries distance or timing.
              </p>
              <p className="mt-2 max-w-prose text-xs text-muted">{result.takeaway}</p>
            </section>
          )}

          <section aria-labelledby="real-world" className="max-w-prose space-y-2 text-sm text-muted">
            <h2 id="real-world" className="font-medium text-fg">
              What real systems add (not implemented here)
            </h2>
            <p>
              <strong className="text-fg">Distance bounding</strong> times the round trip of a challenge so precisely that
              a relay&apos;s extra travel time gives it away. Ultra-wideband (UWB) radios measure time of flight for the
              same reason. Some keys also check motion or ask for a user action before answering.
            </p>
            <p>
              KeyGuard has no radio and doesn&apos;t simulate any of these. It makes no proximity claim, and a valid
              signature here proves only that the key signed this exact challenge.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
