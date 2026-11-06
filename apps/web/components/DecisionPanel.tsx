import type { Decision } from "@/lib/api";

const STEP_LABELS: Record<string, string> = {
  challenge_found: "Challenge exists in this lab",
  challenge_consumed: "Challenge fresh and consumed (single use)",
  key_matches_challenge: "Key matches the challenge",
  key_active_and_bound: "Key active and bound to vehicle",
  signature_valid: "Signature valid over server-rebuilt bytes",
  state_committed: "Vehicle state committed",
};

const STATUS_TEXT = { pass: "PASS", fail: "FAIL", skipped: "SKIP" } as const;
const STATUS_CLASS = { pass: "text-allow", fail: "text-deny", skipped: "text-muted" } as const;

/** Renders the server's decision. Status is always spelled out, never shown by colour alone. */
export function DecisionPanel({ decision }: { decision: Decision }) {
  const allowed = decision.decision === "allow";
  return (
    <section
      aria-live="polite"
      aria-labelledby="decision-heading"
      className={`rounded-lg border p-5 ${allowed ? "border-allow/40" : "border-deny/40"} bg-panel`}
    >
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h2 id="decision-heading" className={`text-lg font-semibold ${allowed ? "text-allow" : "text-deny"}`}>
          {allowed ? `ALLOWED · ${decision.lock_state?.toUpperCase()}` : `DENIED · ${decision.reason}`}
        </h2>
        <p className="font-mono text-xs text-muted">
          {decision.action} · {decision.challenge_id} · {decision.duration_ms} ms (server)
        </p>
      </div>
      <ol className="mt-4 space-y-1.5" aria-label="Server verification trace">
        {decision.trace.map((s, i) => (
          <li key={s.step} className="flex flex-wrap items-baseline gap-x-3 text-sm">
            <span className="w-14 font-mono text-xs text-muted">{String(i + 1).padStart(2, "0")} / 06</span>
            <span className={`w-10 font-mono text-xs ${STATUS_CLASS[s.status]}`}>{STATUS_TEXT[s.status]}</span>
            <span className={s.status === "skipped" ? "text-muted" : ""}>{STEP_LABELS[s.step] ?? s.step}</span>
            {s.detail && <span className="font-mono text-xs text-muted">{s.detail}</span>}
          </li>
        ))}
      </ol>
    </section>
  );
}
