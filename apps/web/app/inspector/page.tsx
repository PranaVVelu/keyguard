"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { DecisionPanel } from "@/components/DecisionPanel";
import { LabMeta, StartLab } from "@/components/LabBar";
import { annotateSignedMessage, splitSignature } from "@/lib/annotate";
import { ApiError, type Action, type Decision } from "@/lib/api";
import { ClientRefusal, performAction, replay, type FlowArtifacts, type FlowStage } from "@/lib/auth-flow";
import { b64urlDecode } from "@/lib/encoding";
import { getKey } from "@/lib/keystore";
import { useLab } from "@/lib/use-lab";
import { useLabKeys } from "@/lib/use-keys";

const ORDER: FlowStage[] = ["challenge", "check", "sign", "verify"];

function describe(e: unknown) {
  return e instanceof ApiError || e instanceof ClientRefusal ? `${e.code}: ${e.message}` : String(e);
}

function Stage({
  n,
  title,
  where,
  state,
  ms,
  children,
  explain,
}: {
  n: number;
  title: string;
  where: "browser" | "server" | "browser → server";
  state: "waiting" | "done" | "failed";
  ms?: number;
  children?: React.ReactNode;
  explain: string;
}) {
  return (
    <li className="rounded-lg border border-line bg-panel p-5" aria-current={state === "waiting" ? undefined : "step"}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-base font-medium">
          <span className="mr-2 font-mono text-xs text-muted">{String(n).padStart(2, "0")} / 07</span>
          {title}
        </h2>
        <span className="font-mono text-xs text-muted">
          {where}
          {ms !== undefined ? ` · ${ms} ms` : ""} ·{" "}
          <span className={state === "done" ? "text-allow" : state === "failed" ? "text-deny" : ""}>
            {state.toUpperCase()}
          </span>
        </span>
      </div>
      <p className="mt-1 max-w-prose text-sm text-muted">{explain}</p>
      {state !== "waiting" && children && <div className="mt-3">{children}</div>}
    </li>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <pre className="overflow-x-auto rounded-md border border-line bg-bg p-3 font-mono text-xs leading-relaxed">{children}</pre>;
}

function Countdown({ expiresAt }: { expiresAt: number }) {
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 250);
    return () => clearInterval(id);
  }, []);
  const left = Math.max(0, Math.ceil(expiresAt - now));
  return (
    <span className={left === 0 ? "text-deny" : ""}>
      {left === 0 ? "expired (by this browser's clock; the server's clock decides)" : `${left}s left`}
    </span>
  );
}

export default function InspectorPage() {
  const { session, ready, start, end, lost, notice } = useLab();
  const { vehicle, usable, refresh } = useLabKeys(session, lost);
  const [selectedKey, setSelectedKey] = useState("");
  const [action, setAction] = useState<Action>("unlock");
  const [art, setArt] = useState<FlowArtifacts | null>(null);
  const [failedAt, setFailedAt] = useState<FlowStage | null>(null);
  const [replayed, setReplayed] = useState<Decision | null>(null);
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const keyId = usable.some((k) => k.id === selectedKey) ? selectedKey : (usable[0]?.id ?? "");

  const run = async () => {
    if (!session || !vehicle || !keyId) return;
    setRunning(true);
    setError(null);
    setFailedAt(null);
    setReplayed(null);
    const req = { vehicleId: vehicle.id, keyId, action };
    setArt({ request: req, timings: {} });
    let last: FlowStage | null = null;
    try {
      const stored = await getKey(keyId);
      if (!stored) throw new ClientRefusal("KEY_NOT_IN_BROWSER", "Private key is not in this browser");
      await performAction(session, req, stored.privateKey, (stage, a) => {
        last = stage;
        setArt({ ...a, timings: { ...a.timings } });
      });
      await refresh();
    } catch (e) {
      setFailedAt(last ? ORDER[ORDER.indexOf(last) + 1] ?? null : "challenge");
      setError(describe(e));
    } finally {
      setRunning(false);
    }
  };

  const doReplay = async () => {
    if (!session || !art) return;
    try {
      setReplayed(await replay(session, art));
      await refresh();
    } catch (e) {
      setError(describe(e));
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

  const stateOf = (stage: FlowStage, present: boolean): "waiting" | "done" | "failed" =>
    failedAt === stage ? "failed" : present ? "done" : "waiting";

  const segments = art?.message ? annotateSignedMessage(art.message) : [];
  const sig = art?.signature ? splitSignature(b64urlDecode(art.signature)) : null;

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Authentication Inspector</h1>
        {session && <LabMeta session={session} onEnd={end} />}
      </header>

      {!ready ? null : !session ? (
        <StartLab onStart={onStart} busy={busy} error={error} notice={notice} />
      ) : usable.length === 0 ? (
        <p className="text-sm">
          No usable key in this browser.{" "}
          <Link href="/keys" className="text-accent underline underline-offset-4">
            Enroll a key
          </Link>{" "}
          to inspect an exchange.
        </p>
      ) : (
        <>
          <section className="flex flex-wrap items-end gap-3 rounded-lg border border-line bg-panel p-5">
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
            <fieldset className="flex flex-col gap-1 text-sm">
              <legend className="text-muted">Action</legend>
              <div className="mt-1 flex rounded-full border border-line p-0.5" role="radiogroup">
                {(["unlock", "lock"] as const).map((a) => (
                  <button
                    key={a}
                    type="button"
                    role="radio"
                    aria-checked={action === a}
                    onClick={() => setAction(a)}
                    className={`rounded-full px-4 py-1.5 font-mono text-xs ${action === a ? "bg-fg text-bg" : "text-muted hover:text-fg"}`}
                  >
                    {a}
                  </button>
                ))}
              </div>
            </fieldset>
            <button
              type="button"
              onClick={run}
              disabled={running}
              className="rounded-md bg-fg px-4 py-2 text-sm font-medium text-bg disabled:opacity-60"
            >
              {running ? "Running…" : `Run ${action} exchange`}
            </button>
            {art?.decision && (
              <button
                type="button"
                onClick={doReplay}
                className="rounded-md border border-line px-4 py-2 text-sm hover:border-deny hover:text-deny"
              >
                Replay this exact response
              </button>
            )}
            <p className="w-full font-mono text-xs text-muted">
              vehicle {vehicle?.id} · currently {vehicle?.lock_state} (from backend)
            </p>
          </section>

          {art && (
            <ol className="space-y-3" aria-label="Protocol timeline">
              <Stage
                n={1}
                title="Request a challenge"
                where="browser → server"
                state={stateOf("challenge", !!art.challenge)}
                ms={art.timings.challenge}
                explain="The browser names the vehicle, key and action it wants. Nothing here is trusted yet."
              >
                <Mono>
                  {JSON.stringify({ vehicle_id: art.request.vehicleId, key_id: art.request.keyId, action: art.request.action }, null, 2)}
                </Mono>
              </Stage>

              <Stage
                n={2}
                title="Server issues a single-use challenge"
                where="server"
                state={stateOf("challenge", !!art.challenge)}
                explain="A fresh 32-byte random nonce, bound to this vehicle, key and action, stored as unused with a 30-second expiry."
              >
                {art.challenge && (
                  <Mono>
                    {`challenge_id  ${art.challenge.challenge_id}\nnonce         ${art.challenge.nonce}\naction        ${art.challenge.action}\nexpires_at    ${art.challenge.expires_at}  (`}
                    <Countdown expiresAt={art.challenge.expires_at} />
                    {")"}
                  </Mono>
                )}
              </Stage>

              <Stage
                n={3}
                title="Browser checks the challenge matches the request"
                where="browser"
                state={stateOf("check", !!art.message)}
                ms={art.timings.check}
                explain="The browser refuses to sign if the server returned a different vehicle, key or action than it asked for."
              >
                <Mono>vehicle_id ✓ · key_id ✓ · action ✓ · protocol kg-auth-v1 ✓</Mono>
              </Stage>

              <Stage
                n={4}
                title="Build the canonical signed bytes"
                where="browser"
                state={stateOf("check", !!art.message)}
                explain="Domain tag, then seven fields, each with a 4-byte big-endian length prefix. The server rebuilds these exact bytes from its own stored row."
              >
                {art.message && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left font-mono text-xs">
                      <thead className="text-muted">
                        <tr>
                          <th className="py-1 pr-3 font-normal">offset</th>
                          <th className="py-1 pr-3 font-normal">field</th>
                          <th className="py-1 pr-3 font-normal">len</th>
                          <th className="py-1 pr-3 font-normal">value (text)</th>
                          <th className="py-1 font-normal">value (hex)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {segments.map((s) => (
                          <tr key={s.label} className="border-t border-line align-top">
                            <td className="py-1 pr-3 text-muted">{s.offset}</td>
                            <td className="py-1 pr-3">{s.label}</td>
                            <td className="py-1 pr-3 text-muted">{s.lengthHex ?? "n/a"}</td>
                            <td className="py-1 pr-3 break-all">{s.text}</td>
                            <td className="py-1 break-all text-muted">{s.valueHex}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <p className="mt-2 font-mono text-xs text-muted">{art.message.length} bytes total</p>
                  </div>
                )}
              </Stage>

              <Stage
                n={5}
                title="Sign with the non-extractable private key"
                where="browser"
                state={stateOf("sign", !!art.signature)}
                ms={art.timings.sign}
                explain="ECDSA P-256 over SHA-256 of those bytes, using the key stored in this browser. The private key itself never leaves Web Crypto."
              >
                {sig && <Mono>{`r  ${sig.r}\ns  ${sig.s}`}</Mono>}
              </Stage>

              <Stage
                n={6}
                title="Submit only the signature and IDs"
                where="browser → server"
                state={stateOf("verify", !!art.decision)}
                ms={art.timings.verify}
                explain="The vehicle and action are not sent again. The server looks them up from the challenge it issued, so they can't be swapped in transit."
              >
                <Mono>
                  {JSON.stringify(
                    { challenge_id: art.challenge?.challenge_id, key_id: art.request.keyId, signature: art.signature },
                    null,
                    2,
                  )}
                </Mono>
              </Stage>

              <Stage
                n={7}
                title="Server verifies and decides"
                where="server"
                state={stateOf("verify", !!art.decision)}
                explain="Consume the challenge atomically, check the key, verify the signature, then and only then change vehicle state, all in one transaction."
              >
                {art.decision && <DecisionPanel decision={art.decision} />}
              </Stage>
            </ol>
          )}

          {replayed && (
            <section aria-live="polite" className="space-y-2">
              <h2 className="text-lg font-medium">Replay of the same response</h2>
              <p className="text-sm text-muted">
                Same challenge ID, same genuine signature, sent again. The challenge was already used, so the server refuses.
              </p>
              <DecisionPanel decision={replayed} />
            </section>
          )}

          {error && (
            <p role="alert" className="font-mono text-xs text-deny">
              {error}
            </p>
          )}
          <p className="text-xs text-muted">
            A valid signature proves possession of the enrolled key, not physical proximity to the car. Relay attacks are
            out of scope.
          </p>
        </>
      )}
    </div>
  );
}
