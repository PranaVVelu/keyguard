"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import {
  ApiError,
  deleteAccount,
  getAccount,
  loginOptions,
  loginVerify,
  logout,
  openSavedLab,
  registerOptions,
  registerVerify,
  saveLab,
  unsaveLab,
  type AccountSummary,
} from "@/lib/api";
import { useLab } from "@/lib/use-lab";
import { createPasskey, getPasskey, passkeysSupported } from "@/lib/webauthn";

function describe(e: unknown): string {
  if (e instanceof ApiError) return `${e.code}: ${e.message}`;
  if (e instanceof DOMException && e.name === "NotAllowedError") return "Passkey prompt was cancelled or timed out";
  return String(e);
}

const date = (t: number) => new Date(t * 1000).toLocaleString();

export default function AccountPage() {
  const router = useRouter();
  const { session, adopt } = useLab();
  const [summary, setSummary] = useState<AccountSummary | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [supported, setSupported] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setSummary(await getAccount());
      setError(null);
    } catch (e) {
      setError(describe(e));
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSupported(passkeysSupported());
    void refresh();
  }, [refresh]);

  const act = async (label: string, fn: () => Promise<void>) => {
    setBusy(label);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(null);
    }
  };

  const onRegister = (e: React.FormEvent) => {
    e.preventDefault();
    void act("register", async () => {
      const { challenge_id, options } = await registerOptions(name.trim());
      setSummary(await registerVerify(challenge_id, await createPasskey(options)));
    });
  };

  const onLogin = () =>
    act("login", async () => {
      const { challenge_id, options } = await loginOptions();
      setSummary(await loginVerify(challenge_id, await getPasskey(options)));
    });

  const currentSaved = summary?.saved_labs.some((l) => l.lab_id === session?.labId) ?? false;

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Account</h1>
        <p className="max-w-prose text-sm text-muted">
          Optional. Labs work without an account; signing in lets you keep up to 10 labs for 30 days and reopen them in
          any browser. Sign-in uses a <strong className="text-fg">passkey</strong>: no password, no email, and your
          passkey only works on this site.
        </p>
      </header>

      {!supported && (
        <p role="alert" className="rounded-md border border-line bg-warn-bg px-3 py-2 text-sm text-warn-fg">
          This browser doesn&apos;t support passkeys here (they need a secure context such as localhost or HTTPS).
        </p>
      )}

      {!loaded ? null : !summary ? (
        <div className="grid gap-4 md:grid-cols-2">
          <section aria-labelledby="signin-heading" className="rounded-lg border border-line bg-panel p-6">
            <h2 id="signin-heading" className="text-lg font-medium">
              Sign in
            </h2>
            <p className="mt-1 text-sm text-muted">Use a passkey you created here before.</p>
            <button
              type="button"
              onClick={onLogin}
              disabled={busy !== null || !supported}
              className="mt-4 rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
            >
              {busy === "login" ? "Waiting for passkey…" : "Sign in with a passkey"}
            </button>
          </section>
          <section aria-labelledby="register-heading" className="rounded-lg border border-line bg-panel p-6">
            <h2 id="register-heading" className="text-lg font-medium">
              Create an account
            </h2>
            <form onSubmit={onRegister} className="mt-3 flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Display name (not an email)</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  maxLength={40}
                  required
                  className="rounded-md border border-line bg-bg px-3 py-2"
                />
              </label>
              <button
                type="submit"
                disabled={busy !== null || !name.trim() || !supported}
                className="rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
              >
                {busy === "register" ? "Waiting for passkey…" : "Create passkey"}
              </button>
            </form>
            <p className="mt-3 text-xs text-muted">
              One passkey per account for now. If you lose it, the account and its saved labs can&apos;t be recovered.
            </p>
          </section>
        </div>
      ) : (
        <>
          <section aria-labelledby="me-heading" className="rounded-lg border border-line bg-panel p-6">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 id="me-heading" className="text-lg font-medium">
                  Signed in as {summary.account.display_name}
                </h2>
                <p className="mt-1 font-mono text-xs text-muted">
                  {summary.account.id} · since {date(summary.account.created_at)}
                </p>
              </div>
              <button
                type="button"
                onClick={() => act("logout", async () => {
                  await logout();
                  setSummary(null);
                })}
                disabled={busy !== null}
                className="rounded-md border border-line px-3 py-1.5 text-sm hover:text-fg"
              >
                Sign out
              </button>
            </div>
            <ul className="mt-4 space-y-1 font-mono text-xs text-muted">
              {summary.passkeys.map((p) => (
                <li key={p.id_prefix}>
                  passkey {p.id_prefix}… · created {date(p.created_at)}
                  {p.last_used_at ? ` · last used ${date(p.last_used_at)}` : ""}
                </li>
              ))}
            </ul>
            <p className="mt-3 text-xs text-muted">
              Your session is an HttpOnly cookie, so scripts on this page can&apos;t read it. It expires after 12 hours.
            </p>
          </section>

          <section aria-labelledby="saved-heading" className="rounded-lg border border-line bg-panel p-6">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 id="saved-heading" className="text-lg font-medium">
                Saved labs <span className="font-mono text-xs text-muted">({summary.saved_labs.length} of 10)</span>
              </h2>
              {session && !currentSaved && (
                <button
                  type="button"
                  onClick={() => act("save", async () => setSummary(await saveLab(session)))}
                  disabled={busy !== null}
                  className="rounded-md bg-fg px-3 py-1.5 text-sm font-medium text-bg disabled:opacity-60"
                >
                  {busy === "save" ? "Saving…" : `Save current lab (${session.labId.slice(0, 12)}…)`}
                </button>
              )}
            </div>
            {summary.saved_labs.length === 0 ? (
              <p className="mt-3 text-sm text-muted">
                No saved labs. Start a lab, then come back here to save it.
              </p>
            ) : (
              <ul className="mt-4 space-y-3">
                {summary.saved_labs.map((l) => (
                  <li key={l.lab_id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line p-3">
                    <div>
                      <p className="text-sm">
                        {l.vehicle_name} · <span className="uppercase">{l.lock_state}</span> ·{" "}
                        {l.event_count} events
                        {session?.labId === l.lab_id && <span className="ml-2 text-xs text-accent">(open in this tab)</span>}
                      </p>
                      <p className="font-mono text-xs text-muted">
                        {l.lab_id} · kept until {date(l.expires_at)}
                      </p>
                    </div>
                    <span className="flex gap-2">
                      <button
                        type="button"
                        aria-label={`Open saved lab ${l.lab_id}`}
                        onClick={() => act(`open-${l.lab_id}`, async () => {
                          adopt(await openSavedLab(l.lab_id));
                          router.push("/");
                        })}
                        disabled={busy !== null}
                        className="rounded-md border border-line px-3 py-1.5 text-sm hover:text-fg"
                      >
                        Open
                      </button>
                      <button
                        type="button"
                        aria-label={`Stop saving lab ${l.lab_id}`}
                        onClick={() => act(`unsave-${l.lab_id}`, async () => setSummary(await unsaveLab(l.lab_id)))}
                        disabled={busy !== null}
                        className="rounded-md border border-line px-3 py-1.5 text-sm text-muted hover:text-fg"
                      >
                        Stop saving
                      </button>
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-xs text-muted">
              Opening a saved lab issues it a fresh access token, so any other tab still using the old one is signed out
              of that lab. Private keys stay in the browser that created them; in another browser, enroll new keys.
            </p>
          </section>

          <section aria-labelledby="danger-heading" className="rounded-lg border border-deny/40 bg-panel p-6">
            <h2 id="danger-heading" className="text-lg font-medium">
              Delete account
            </h2>
            <p className="mt-1 text-sm text-muted">
              Deletes your account, passkey record, sessions and every saved lab with all its history. This can&apos;t be
              undone. Type <span className="font-mono text-fg">DELETE</span> to confirm.
            </p>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <label className="flex flex-col gap-1 text-sm">
                <span className="text-muted">Confirmation</span>
                <input
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  className="rounded-md border border-line bg-bg px-3 py-2 font-mono"
                />
              </label>
              <button
                type="button"
                disabled={confirmText !== "DELETE" || busy !== null}
                onClick={() => act("delete", async () => {
                  await deleteAccount();
                  setSummary(null);
                  setConfirmText("");
                })}
                className="rounded-md border border-deny px-4 py-2 text-sm font-medium text-deny disabled:opacity-40"
              >
                Delete account and saved labs
              </button>
            </div>
          </section>
        </>
      )}

      {error && (
        <p role="alert" className="font-mono text-xs text-deny">
          {error}
        </p>
      )}
    </div>
  );
}
