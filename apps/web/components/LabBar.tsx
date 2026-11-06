"use client";

import type { LabSession } from "@/lib/lab-session";

/** Monospace metadata line shown under page headings (design direction: bold heading + mono meta). */
export function LabMeta({ session, onEnd }: { session: LabSession; onEnd: () => void }) {
  const expires = new Date(session.expiresAt * 1000).toLocaleString();
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs text-muted">
      <span>{session.labId}</span>
      <span aria-hidden="true">/</span>
      <span>expires {expires}</span>
      <span aria-hidden="true">/</span>
      <span>kg-auth-v1</span>
      <button type="button" onClick={onEnd} className="ml-2 rounded border border-line px-2 py-0.5 hover:text-fg">
        End lab
      </button>
    </div>
  );
}

export function StartLab({ onStart, busy, error }: { onStart: () => void; busy: boolean; error: string | null }) {
  return (
    <section className="rounded-lg border border-line bg-panel p-8">
      <h2 className="text-lg font-medium">No lab yet</h2>
      <p className="mt-2 max-w-prose text-sm text-muted">
        A lab is a disposable, isolated sandbox with one fictional vehicle. Its access token stays in this browser tab
        only, and the lab expires after 24 hours.
      </p>
      <button
        type="button"
        onClick={onStart}
        disabled={busy}
        className="mt-6 rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
      >
        {busy ? "Creating lab…" : "Start a lab"}
      </button>
      {error && (
        <p role="alert" className="mt-3 font-mono text-xs text-deny">
          {error}
        </p>
      )}
    </section>
  );
}
