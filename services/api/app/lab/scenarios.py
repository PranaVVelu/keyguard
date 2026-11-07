"""Attack Lab scenarios: vulnerable vs hardened, side by side, on disposable state (spec F05, D-005).

Each run builds fresh, throwaway state for BOTH modes:
  * vulnerable: app.lab.vulnerable.VulnerableVerifier (in memory)
  * hardened:   the real production engine (app.security.authenticate) against a temporary
                SQLite database that is deleted afterwards
The caller's lab database is never read or modified by a scenario. Only the summary row in
lab_runs is written there.
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.db import make_engine
from app.evidence.client_sim import SimulatedClientKey
from app.lab.vulnerable.verifier import VulnerableVerifier
from app.security.authenticate import authenticate
from app.security.challenges import issue_challenge
from app.security.keys import enroll_key
from app.security.labs import create_lab
from app.security.protocol import SignedFields, encode_signed_message


@dataclass
class Step:
    n: int
    actor: str  # owner | attacker
    label: str
    decision: str
    reason: str | None
    lock_state: str


@dataclass
class ModeRun:
    mode: str  # vulnerable | hardened
    steps: list[Step] = field(default_factory=list)
    final_lock_state: str = "locked"
    attack_decision: str = ""
    attack_reason: str | None = None


@dataclass
class ScenarioInfo:
    id: str
    title: str
    description: str
    expected: dict[str, str]  # mode → expected decision for the attack step


SCENARIOS: dict[str, ScenarioInfo] = {
    "replay": ScenarioInfo(
        id="replay",
        title="Replay a captured unlock",
        description=(
            "The owner unlocks, then locks the car. An attacker who captured the owner's earlier, valid unlock "
            "response resubmits it unchanged. The signature is genuine, so only single-use enforcement can stop it."
        ),
        expected={"vulnerable": "allow", "hardened": "deny"},
    ),
}


def _sign(key: SimulatedClientKey, f: SignedFields) -> str:
    return key.sign_p1363(encode_signed_message(f))


def _replay_vulnerable(now: int) -> ModeRun:
    run = ModeRun("vulnerable")
    v = VulnerableVerifier()
    key = SimulatedClientKey()
    vehicle_id, key_id = "veh_" + "V" * 22, "key_" + "V" * 22

    unlock = v.issue(vehicle_id=vehicle_id, key_id=key_id, spki_b64url=key.spki_b64url, action="unlock", now=now)
    captured = (unlock.challenge_id, _sign(key, unlock))
    d, r = v.verify(challenge_id=captured[0], signature=captured[1])
    run.steps.append(Step(1, "owner", "Owner unlocks (response captured by attacker)", d, r, v.lock_state))

    lock = v.issue(vehicle_id=vehicle_id, key_id=key_id, spki_b64url=key.spki_b64url, action="lock", now=now)
    d, r = v.verify(challenge_id=lock.challenge_id, signature=_sign(key, lock))
    run.steps.append(Step(2, "owner", "Owner locks and walks away", d, r, v.lock_state))

    d, r = v.verify(challenge_id=captured[0], signature=captured[1])
    run.steps.append(Step(3, "attacker", "Attacker replays the captured unlock", d, r, v.lock_state))
    run.attack_decision, run.attack_reason, run.final_lock_state = d, r, v.lock_state
    return run


def _replay_hardened(now: int) -> ModeRun:
    run = ModeRun("hardened")
    with tempfile.TemporaryDirectory() as tmp:
        engine = make_engine(f"sqlite:///{Path(tmp) / 'scenario.db'}")
        try:
            key = SimulatedClientKey()
            clock = lambda: now  # noqa: E731
            with engine.begin() as conn:
                lab = create_lab(conn, now=now)
                key_id = enroll_key(
                    conn, lab_id=lab.lab_id, vehicle_id=lab.vehicle_id, spki_b64url=key.spki_b64url, label="owner", now=now
                )

            def issue(action: str) -> SignedFields:
                with engine.begin() as conn:
                    c = issue_challenge(conn, lab_id=lab.lab_id, vehicle_id=lab.vehicle_id, key_id=key_id, action=action, now=now)
                return c.signed_fields()

            def submit(chl_id: str, sig: str):
                return authenticate(engine, lab_id=lab.lab_id, challenge_id=chl_id, key_id=key_id, signature=sig, clock=clock)

            unlock = issue("unlock")
            captured = (unlock.challenge_id, _sign(key, unlock))
            d = submit(*captured)
            run.steps.append(Step(1, "owner", "Owner unlocks (response captured by attacker)", d.decision, d.reason, d.lock_state))

            lock = issue("lock")
            d = submit(lock.challenge_id, _sign(key, lock))
            run.steps.append(Step(2, "owner", "Owner locks and walks away", d.decision, d.reason, d.lock_state))

            d = submit(*captured)
            run.steps.append(Step(3, "attacker", "Attacker replays the captured unlock", d.decision, d.reason, d.lock_state))
            run.attack_decision, run.attack_reason, run.final_lock_state = d.decision, d.reason, d.lock_state
        finally:
            engine.dispose()
    return run


_RUNNERS = {"replay": (_replay_vulnerable, _replay_hardened)}


def run_scenario(scenario_id: str, *, now: int | None = None) -> dict:
    info = SCENARIOS[scenario_id]
    now = int(time.time()) if now is None else now
    started = time.perf_counter()
    vulnerable_fn, hardened_fn = _RUNNERS[scenario_id]
    runs = [vulnerable_fn(now), hardened_fn(now)]
    actual = {r.mode: r.attack_decision for r in runs}
    return {
        "scenario": info.id,
        "title": info.title,
        "description": info.description,
        "expected": info.expected,
        "actual": actual,
        "matches_expected": actual == info.expected,
        "runs": [asdict(r) for r in runs],
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }
