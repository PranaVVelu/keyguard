"""Mandatory hardened test matrix runner (spec §7) producing structured, reproducible evidence.

For each scenario it records the scenario ID, expected decision, observed decision, reason, timing
and outcome. Each scenario runs against a fresh, isolated app and database through the real HTTP API.

Outcome classes (spec §7):
  pass                    observed matches expected
  security_failure        unauthorized acceptance: an expected deny/reject was allowed, a deny changed
                          vehicle state, or more than one concurrent submission succeeded
  functional_failure      a valid request was denied, or a deny happened for an unexpected reason
  infrastructure_failure  the scenario itself errored, so the result is untrustworthy

    uv run python -m app.evidence.matrix --json ../../docs/evidence/matrix-latest.json
Exit code is non-zero unless every scenario passes.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.evidence.client_sim import SimulatedClientKey
from app.security.authenticate import authenticate
from app.security.challenges import CHALLENGE_TTL_SECONDS
from app.security.encoding import b64url_encode, new_id
from app.security.protocol import SignedFields, encode_signed_message

START = 1_793_923_200


@dataclass
class Observation:
    decision: str  # allow | deny | reject | multi
    reason: str | None = None
    state_changed: bool = False
    allows: int | None = None  # for concurrency scenarios
    attempts: int | None = None


@dataclass
class Scenario:
    id: str
    title: str
    expected: str  # allow | deny | reject | at_most_one_allow
    expected_reasons: tuple[str, ...] = ()
    run: Callable[[Driver], Observation] = field(repr=False, default=None)  # type: ignore[assignment]


@dataclass
class Result:
    id: str
    title: str
    expected: str
    expected_reasons: list[str]
    observed: str | None
    reason: str | None
    state_changed: bool | None
    outcome: str
    note: str | None
    duration_ms: float


class Driver:
    """A fresh app + database + simulated client per scenario."""

    def __init__(self, tmpdir: Path) -> None:
        from fastapi.testclient import TestClient

        from app.main import create_app

        self.t = START
        self.app = create_app(f"sqlite:///{tmpdir / 'matrix.db'}", clock=lambda: self.t, cleanup_interval=0)
        self.http = TestClient(self.app)
        lab = self.http.post("/api/labs").json()
        self.lab_id, self.token = lab["lab_id"], lab["lab_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self.vehicle_id = self.get(f"/api/labs/{self.lab_id}/vehicles").json()["vehicles"][0]["id"]
        self.key = SimulatedClientKey()
        self.key_id = self.post(
            f"/api/labs/{self.lab_id}/keys",
            {"vehicle_id": self.vehicle_id, "public_key": self.key.spki_b64url, "label": "matrix"},
        ).json()["id"]

    def close(self) -> None:
        self.http.close()
        self.app.state.engine.dispose()

    def get(self, path: str, headers: dict | None = None):
        return self.http.get(path, headers=headers or self.headers)

    def post(self, path: str, body=None, headers: dict | None = None):
        return self.http.post(path, json=body, headers=headers or self.headers)

    def lock_state(self) -> str:
        return self.get(f"/api/labs/{self.lab_id}/vehicles").json()["vehicles"][0]["lock_state"]

    def challenge(self, action: str = "unlock", key_id: str | None = None) -> dict:
        resp = self.post(
            f"/api/labs/{self.lab_id}/challenges",
            {"vehicle_id": self.vehicle_id, "key_id": key_id or self.key_id, "action": action},
        )
        if resp.status_code != 201:
            raise _HttpDenied(resp)
        return resp.json()

    def sign(self, chl: dict, key: SimulatedClientKey | None = None, **override) -> str:
        f = {k: chl[k] for k in ("vehicle_id", "key_id", "challenge_id", "nonce", "action", "expires_at")}
        return (key or self.key).sign_p1363(encode_signed_message(SignedFields(**{**f, **override})))

    def submit(self, chl_id: str, signature: str, key_id: str | None = None, headers: dict | None = None) -> Observation:
        before = self.lock_state()
        resp = self.post(
            f"/api/labs/{self.lab_id}/authenticate",
            {"challenge_id": chl_id, "key_id": key_id or self.key_id, "signature": signature},
            headers=headers,
        )
        changed = self.lock_state() != before
        if resp.status_code == 200:
            body = resp.json()
            return Observation(body["decision"], body["reason"], changed)
        return _from_http_error(resp, changed)


class _HttpDenied(Exception):
    def __init__(self, resp) -> None:
        super().__init__(resp.text)
        self.resp = resp


def _from_http_error(resp, changed: bool = False) -> Observation:
    code = (resp.json().get("error") or {}).get("code") if resp.headers.get("content-type", "").startswith("application/json") else None
    decision = "reject" if code == "REQUEST_INVALID" else "deny"
    return Observation(decision, code or f"HTTP_{resp.status_code}", changed)


def _denied_at_issue(fn: Callable[[Driver], Observation]) -> Callable[[Driver], Observation]:
    def wrapped(d: Driver) -> Observation:
        try:
            return fn(d)
        except _HttpDenied as exc:
            return _from_http_error(exc.resp)

    return wrapped


# --- Scenarios ----------------------------------------------------------------------------


def _mx01(d: Driver) -> Observation:
    chl = d.challenge("unlock")
    return d.submit(chl["challenge_id"], d.sign(chl))


def _mx02(d: Driver) -> Observation:
    chl = d.challenge()
    return d.submit(chl["challenge_id"], d.sign(chl, key=SimulatedClientKey()))


def _mx03(d: Driver) -> Observation:
    chl = d.challenge()
    d.post(f"/api/labs/{d.lab_id}/keys/{d.key_id}/revoke")
    return d.submit(chl["challenge_id"], d.sign(chl))


def _mx04(d: Driver) -> Observation:
    chl = d.challenge()
    d.t += CHALLENGE_TTL_SECONDS
    return d.submit(chl["challenge_id"], d.sign(chl))


def _mx05(d: Driver) -> Observation:
    chl = d.challenge("unlock")
    sig = d.sign(chl)
    first = d.submit(chl["challenge_id"], sig)
    if first.decision != "allow":
        raise RuntimeError(f"setup: first submission was {first.decision}/{first.reason}")
    lock = d.challenge("lock")
    d.submit(lock["challenge_id"], d.sign(lock))
    return d.submit(chl["challenge_id"], sig)  # replay of the captured unlock


def _mx06(d: Driver) -> Observation:
    chl = d.challenge()
    return d.submit(chl["challenge_id"], d.sign(chl, vehicle_id=new_id("veh")))


def _mx07(d: Driver) -> Observation:
    chl = d.challenge("lock")
    return d.submit(chl["challenge_id"], d.sign(chl, action="unlock"))


def _mx08(d: Driver, workers: int = 16) -> Observation:
    chl = d.challenge()
    sig = d.sign(chl)
    barrier = threading.Barrier(workers)
    out: list[str] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def attempt() -> None:
        try:
            barrier.wait()
            r = authenticate(
                d.app.state.engine, lab_id=d.lab_id, challenge_id=chl["challenge_id"],
                key_id=d.key_id, signature=sig, clock=d.app.state.clock,
            )
            with lock:
                out.append(r.decision)
        except BaseException as exc:  # noqa: BLE001 - surfaced as infrastructure failure
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    if errors or len(out) != workers:
        raise RuntimeError(f"concurrency harness incomplete: {len(out)}/{workers} results, errors={errors[:1]}")
    allows = out.count("allow")
    return Observation("multi", f"{allows} allow / {workers - allows} deny", allows > 0, allows=allows, attempts=workers)


def _mx09(d: Driver) -> Observation:
    chl = d.challenge(key_id=new_id("key"))  # raises _HttpDenied → deny
    return d.submit(chl["challenge_id"], d.sign(chl))


def _mx10(d: Driver) -> Observation:
    chl = d.challenge()
    before = d.lock_state()
    resp = d.post(
        f"/api/labs/{d.lab_id}/authenticate",
        {"challenge_id": chl["challenge_id"], "key_id": d.key_id, "signature": d.sign(chl), "decision": "allow"},
    )
    if resp.status_code == 200:
        body = resp.json()
        return Observation(body["decision"], body["reason"], d.lock_state() != before)
    return _from_http_error(resp, d.lock_state() != before)


def _mx11(d: Driver) -> Observation:
    chl = d.challenge()
    other = d.http.post("/api/labs").json()
    return d.submit(chl["challenge_id"], d.sign(chl), headers={"Authorization": f"Bearer {other['lab_token']}"})


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("MX-01", "Active key + fresh challenge", "allow", (), _mx01),
    Scenario("MX-02", "Incorrect signature", "deny", ("SIGNATURE_INVALID",), _mx02),
    Scenario("MX-03", "Revoked key", "deny", ("KEY_REVOKED",), _mx03),
    Scenario("MX-04", "Expired challenge", "deny", ("CHALLENGE_EXPIRED",), _mx04),
    Scenario("MX-05", "Consumed challenge replay", "deny", ("CHALLENGE_CONSUMED",), _mx05),
    Scenario("MX-06", "Wrong vehicle", "deny", ("SIGNATURE_INVALID", "VEHICLE_MISMATCH"), _mx06),
    Scenario("MX-07", "Wrong requested action", "deny", ("SIGNATURE_INVALID",), _mx07),
    Scenario("MX-08", "Two+ concurrent submissions (16 threads)", "at_most_one_allow", (), _mx08),
    Scenario("MX-09", "Unknown key", "deny", ("KEY_UNKNOWN", "KEY_MISMATCH"), _denied_at_issue(_mx09)),
    Scenario("MX-10", "Malformed payload (client-asserted decision field)", "reject", ("REQUEST_INVALID",), _mx10),
    Scenario("MX-11", "Cross-lab request", "deny", ("LAB_NOT_FOUND", "CHALLENGE_NOT_FOUND"), _mx11),
)


def classify(s: Scenario, o: Observation) -> tuple[str, str | None]:
    if s.expected == "at_most_one_allow":
        if (o.allows or 0) > 1:
            return "security_failure", f"{o.allows} concurrent submissions were allowed"
        if o.allows == 0:
            return "functional_failure", "no submission succeeded"
        return "pass", None
    if s.expected == "allow":
        return ("pass", None) if o.decision == "allow" else ("functional_failure", f"valid request denied: {o.reason}")
    # expected deny / reject
    if o.decision == "allow":
        return "security_failure", "unauthorized acceptance"
    if o.state_changed:
        return "security_failure", "vehicle state changed on a non-allow decision"
    if o.decision != s.expected:
        return "functional_failure", f"expected {s.expected}, got {o.decision}"
    if s.expected_reasons and o.reason not in s.expected_reasons:
        return "functional_failure", f"denied for an unexpected reason: {o.reason}"
    return "pass", None


def run_scenario(s: Scenario) -> Result:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        driver = None
        try:
            driver = Driver(Path(tmp))
            o = s.run(driver)
            outcome, note = classify(s, o)
            observed, reason, changed = o.decision, o.reason, o.state_changed
        except Exception as exc:  # noqa: BLE001
            outcome, note = "infrastructure_failure", "".join(traceback.format_exception_only(exc)).strip()
            observed = reason = changed = None
        finally:
            if driver is not None:
                driver.close()
    return Result(
        s.id, s.title, s.expected, list(s.expected_reasons), observed, reason, changed, outcome, note,
        round((time.perf_counter() - started) * 1000, 1),
    )


def run_matrix(scenarios: tuple[Scenario, ...] = SCENARIOS) -> dict:
    results = [run_scenario(s) for s in scenarios]
    counts: dict[str, int] = {}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:  # noqa: BLE001
        sha = ""
    return {
        "matrix": "keyguard-hardened-v1",
        "spec": "KeyGuard spec v1.0 §7",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": sha or None,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "summary": {"total": len(results), **counts},
        "results": [asdict(r) for r in results],
        "coverage_note": (
            "Curated scenarios only; passing does not prove universal security. "
            "Relay/proximity attacks are out of scope. Concurrency proven on SQLite."
        ),
    }


def to_markdown(report: dict) -> str:
    lines = [
        f"Matrix `{report['matrix']}` · commit `{report['git_commit']}` · {report['generated_at']} · "
        f"Python {report['python']} · {report['platform']}",
        "",
        "| ID | Scenario | Expected | Observed | Reason | Outcome | ms |",
        "|----|----------|----------|----------|--------|---------|----|",
    ]
    for r in report["results"]:
        mark = "✅ pass" if r["outcome"] == "pass" else f"❌ {r['outcome']}"
        lines.append(
            f"| {r['id']} | {r['title']} | {r['expected']} | {r['observed']} | {r['reason'] or '—'} | {mark} | {r['duration_ms']} |"
        )
    s = report["summary"]
    lines += ["", f"**{s.get('pass', 0)}/{s['total']} passed.** " + report["coverage_note"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", type=Path, help="write the JSON report here")
    ap.add_argument("--markdown", type=Path, help="write a Markdown table here")
    args = ap.parse_args(argv)

    report = run_matrix()
    md = to_markdown(report)
    print(md)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(md + "\n")
    return 0 if report["summary"].get("pass", 0) == report["summary"]["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
