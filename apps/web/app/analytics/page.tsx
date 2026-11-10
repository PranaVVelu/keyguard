"use client";

import { useCallback, useEffect, useState } from "react";

import { LabMeta, StartLab } from "@/components/LabBar";
import {
  ApiError,
  getEventSummary,
  listEvents,
  type EventCategory,
  type EventPage,
  type EventSummary,
} from "@/lib/api";
import { describeReason, eventLabel, eventQueryString, MAX_SEARCH_LENGTH, PAGE_SIZE, percent } from "@/lib/events";
import { useLab } from "@/lib/use-lab";

const CATEGORIES: { id: EventCategory; label: string }[] = [
  { id: "authentication", label: "Authentication" },
  { id: "challenge", label: "Challenge issuance" },
  { id: "key", label: "Key enrollment & revocation" },
  { id: "scenario", label: "Attack Lab scenarios" },
];

function describe(e: unknown) {
  return e instanceof ApiError ? `${e.code}: ${e.message}` : String(e);
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: "allow" | "deny" }) {
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={`mt-1 font-mono text-2xl ${tone === "allow" ? "text-allow" : tone === "deny" ? "text-deny" : ""}`}>
        {value}
      </dd>
    </div>
  );
}

function PassFailBar({ pass, fail }: { pass: number; fail: number }) {
  const total = pass + fail;
  return (
    <div className="flex h-2 w-full overflow-hidden rounded-full bg-bg" aria-hidden="true">
      {total > 0 && (
        <>
          <div className="bg-allow" style={{ width: `${percent(pass, total)}%` }} />
          <div className="bg-deny" style={{ width: `${100 - percent(pass, total)}%` }} />
        </>
      )}
    </div>
  );
}

export default function AnalyticsPage() {
  const { session, ready, start, end } = useLab();
  const [summary, setSummary] = useState<EventSummary | null>(null);
  const [page, setPage] = useState<EventPage | null>(null);
  const [category, setCategory] = useState<EventCategory | "">("");
  const [result, setResult] = useState<"pass" | "fail" | "">("");
  const [reason, setReason] = useState("");
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Debounce typing so the log isn't re-queried on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(search);
      setOffset(0);
    }, 250);
    return () => clearTimeout(t);
  }, [search]);

  const load = useCallback(async () => {
    if (!session) return;
    try {
      const [s, p] = await Promise.all([
        getEventSummary(session),
        listEvents(session, eventQueryString({ category, result, reason, q, offset })),
      ]);
      setSummary(s);
      setPage(p);
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.code === "LAB_NOT_FOUND") end();
      setError(describe(e));
    }
  }, [session, category, result, reason, q, offset, end]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

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

  const filterBy = (next: { category?: EventCategory | ""; result?: "pass" | "fail" | ""; reason?: string }) => {
    if (next.category !== undefined) setCategory(next.category);
    if (next.result !== undefined) setResult(next.result);
    if (next.reason !== undefined) setReason(next.reason);
    setOffset(0);
  };

  const filtersActive = Boolean(category || result || reason || q);
  const auth = summary?.authentication;

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Security Analytics</h1>
        {session && <LabMeta session={session} onEnd={end} />}
        <p className="max-w-prose text-sm text-muted">
          Every decision the backend recorded in this lab: IDs, outcomes and reason codes only. Tokens, nonces, keys and
          signatures are never logged. Counts describe this lab&apos;s curated activity, not real-world security.
        </p>
      </header>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={error} />
      ) : (
        <>
          {summary && auth && (
            <dl className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
              <Stat label="Events" value={String(summary.total)} />
              <Stat label="Pass" value={String(summary.pass)} tone="allow" />
              <Stat label="Fail" value={String(summary.fail)} tone={summary.fail ? "deny" : undefined} />
              <Stat label="Auth allowed" value={String(auth.allowed)} tone="allow" />
              <Stat label="Auth denied" value={String(auth.denied)} tone={auth.denied ? "deny" : undefined} />
              <Stat
                label="Auth median / p95"
                value={auth.median_ms === null ? "—" : `${auth.median_ms}/${auth.p95_ms} ms`}
              />
            </dl>
          )}

          {summary && (
            <div className="grid gap-4 lg:grid-cols-2">
              <section aria-labelledby="by-cat" className="rounded-lg border border-line bg-panel p-5">
                <h2 id="by-cat" className="font-medium">
                  Pass / fail by category
                </h2>
                <ul className="mt-4 space-y-3">
                  {CATEGORIES.map(({ id, label }) => {
                    const c = summary.by_category[id];
                    return (
                      <li key={id}>
                        <button
                          type="button"
                          onClick={() => filterBy({ category: category === id ? "" : id })}
                          aria-pressed={category === id}
                          className="w-full rounded-md p-1 text-left hover:bg-bg aria-pressed:bg-bg"
                        >
                          <span className="flex justify-between text-sm">
                            <span>{label}</span>
                            <span className="font-mono text-xs">
                              <span className="text-allow">{c.pass} pass</span>
                              <span className="text-muted"> · </span>
                              <span className={c.fail ? "text-deny" : "text-muted"}>{c.fail} fail</span>
                            </span>
                          </span>
                          <span className="mt-1.5 block">
                            <PassFailBar pass={c.pass} fail={c.fail} />
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </section>

              <section aria-labelledby="fail-cat" className="rounded-lg border border-line bg-panel p-5">
                <h2 id="fail-cat" className="font-medium">
                  Failure categories
                </h2>
                {summary.failure_reasons.length === 0 ? (
                  <p className="mt-4 text-sm text-muted">
                    No failures yet. Try a replay in the Inspector or a scenario in the Attack Lab.
                  </p>
                ) : (
                  <ol className="mt-4 space-y-1">
                    {summary.failure_reasons.map((r) => (
                      <li key={r.reason}>
                        <button
                          type="button"
                          onClick={() => filterBy({ reason: reason === r.reason ? "" : r.reason })}
                          aria-pressed={reason === r.reason}
                          className="flex w-full items-baseline gap-3 rounded-md p-1.5 text-left hover:bg-bg aria-pressed:bg-bg"
                        >
                          <span className="w-8 shrink-0 text-right font-mono text-sm text-deny">{r.count}</span>
                          <span>
                            <span className="block font-mono text-xs">{r.reason}</span>
                            <span className="block text-xs text-muted">{describeReason(r.reason)}</span>
                          </span>
                        </button>
                      </li>
                    ))}
                  </ol>
                )}
              </section>
            </div>
          )}

          <section aria-labelledby="log" className="rounded-lg border border-line bg-panel p-5">
            <div className="flex flex-wrap items-end gap-3">
              <h2 id="log" className="mr-auto font-medium">
                Event log
              </h2>
              <label className="flex flex-col gap-1 text-xs text-muted">
                Search
                <input
                  type="search"
                  value={search}
                  maxLength={MAX_SEARCH_LENGTH}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="ID, type, reason…"
                  className="w-56 rounded-md border border-line bg-bg px-3 py-1.5 font-mono text-sm text-fg"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-muted">
                Category
                <select
                  value={category}
                  onChange={(e) => filterBy({ category: e.target.value as EventCategory | "" })}
                  className="rounded-md border border-line bg-bg px-3 py-1.5 text-sm text-fg"
                >
                  <option value="">All</option>
                  {CATEGORIES.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs text-muted">
                Result
                <select
                  value={result}
                  onChange={(e) => filterBy({ result: e.target.value as "pass" | "fail" | "" })}
                  className="rounded-md border border-line bg-bg px-3 py-1.5 text-sm text-fg"
                >
                  <option value="">All</option>
                  <option value="pass">Pass</option>
                  <option value="fail">Fail</option>
                </select>
              </label>
              <button
                type="button"
                onClick={() => void load()}
                className="rounded-md border border-line px-3 py-1.5 text-sm hover:text-fg"
              >
                Refresh
              </button>
            </div>

            {(reason || filtersActive) && (
              <p className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted">
                {reason && (
                  <span className="rounded-full border border-line px-2 py-0.5 font-mono">reason = {reason}</span>
                )}
                <button
                  type="button"
                  onClick={() => {
                    setSearch("");
                    setQ("");
                    filterBy({ category: "", result: "", reason: "" });
                  }}
                  className="underline-offset-4 hover:text-fg hover:underline"
                >
                  Clear filters
                </button>
              </p>
            )}

            {error && (
              <p role="alert" className="mt-4 font-mono text-xs text-deny">
                {error}
              </p>
            )}

            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Security events, newest first</caption>
                <thead className="text-xs text-muted">
                  <tr className="border-b border-line">
                    <th scope="col" className="py-2 pr-4 font-normal">Time</th>
                    <th scope="col" className="py-2 pr-4 font-normal">Event</th>
                    <th scope="col" className="py-2 pr-4 font-normal">Result</th>
                    <th scope="col" className="py-2 pr-4 font-normal">Reason</th>
                    <th scope="col" className="py-2 pr-4 font-normal">Key</th>
                    <th scope="col" className="py-2 text-right font-normal">ms</th>
                  </tr>
                </thead>
                <tbody aria-live="polite">
                  {page?.events.map((e) => (
                    <tr key={e.id} className="border-b border-line/60 align-top">
                      <td className="py-2 pr-4 font-mono text-xs text-muted">
                        {new Date(e.created_at * 1000).toLocaleTimeString()}
                      </td>
                      <td className="py-2 pr-4">
                        {eventLabel(e.event_type)}
                        <span className="block font-mono text-[11px] text-muted">{e.id}</span>
                      </td>
                      <td className="py-2 pr-4">
                        <span
                          className={`font-mono text-xs font-semibold uppercase ${
                            e.result === "pass" ? "text-allow" : "text-deny"
                          }`}
                        >
                          {e.outcome.replace("_", " ")}
                        </span>
                      </td>
                      <td className="py-2 pr-4">
                        {e.reason ? (
                          <>
                            <span className="font-mono text-xs">{e.reason}</span>
                            <span className="block text-xs text-muted">{describeReason(e.reason)}</span>
                          </>
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs text-muted">{e.key_id ?? "—"}</td>
                      <td className="py-2 text-right font-mono text-xs text-muted">{e.duration_ms ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {page && page.events.length === 0 && (
                <p className="py-6 text-center text-sm text-muted">
                  {filtersActive ? "No events match these filters." : "No events yet in this lab."}
                </p>
              )}
            </div>

            {page && page.total > 0 && (
              <div className="mt-4 flex items-center justify-between font-mono text-xs text-muted">
                <span>
                  {page.offset + 1}–{page.offset + page.events.length} of {page.total}
                </span>
                <span className="flex gap-2">
                  <button
                    type="button"
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                    className="rounded border border-line px-2 py-1 hover:text-fg disabled:opacity-40"
                  >
                    ← Newer
                  </button>
                  <button
                    type="button"
                    disabled={offset + PAGE_SIZE >= page.total}
                    onClick={() => setOffset(offset + PAGE_SIZE)}
                    className="rounded border border-line px-2 py-1 hover:text-fg disabled:opacity-40"
                  >
                    Older →
                  </button>
                </span>
              </div>
            )}
            <p className="mt-3 text-xs text-muted">
              Denied authentications don&apos;t record the key ID the caller claimed, so an attacker can&apos;t attribute
              failures to someone else&apos;s key. Labs and their events are deleted when the lab expires (24 h), and
              each lab keeps at most its 2,000 newest events.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
