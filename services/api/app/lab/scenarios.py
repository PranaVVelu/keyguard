"""Attack Lab scenarios: vulnerable vs hardened, side by side, on disposable state (F05, F09, F10, F11, D-005).

Each run builds fresh, throwaway state for BOTH modes:
  * vulnerable: an in-memory verifier from app.lab.vulnerable (VulnerableVerifier, or ClientBytesVerifier
                for the substitute scenario)
  * hardened:   the real production engine (app.security.authenticate) against a temporary
                SQLite database that is deleted afterwards
The caller's lab database is never read or modified by a scenario. Only the summary row in
lab_runs is written there.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.db import make_engine
from app.evidence.client_sim import SimulatedClientKey
from app.lab.vulnerable.client_bytes import ClientBytesVerifier
from app.lab.vulnerable.fob import CounterlessFobReceiver
from app.lab.vulnerable.verifier import VulnerableVerifier
from app.security.authenticate import authenticate
from app.security.challenges import issue_challenge
from app.security.encoding import b64url_decode, b64url_encode
from app.security.fob import press_fob
from app.security.keys import enroll_key
from app.security.labs import create_lab
from app.security.protocol import FobFields, SignedFields, encode_fob_message, encode_signed_message


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
    attack_label: str  # what the attacker submits, for the outcome line ("Replay ACCEPTED")
    mode_notes: dict[str, str]  # mode → what that verifier does, in this scenario's terms
    takeaway: str  # one-paragraph lesson shown under the result


SCENARIOS: dict[str, ScenarioInfo] = {
    "replay": ScenarioInfo(
        id="replay",
        title="Replay a captured unlock",
        description=(
            "The owner unlocks, then locks the car. An attacker who captured the owner's earlier, valid unlock "
            "response resubmits it unchanged. The signature is genuine, so only single-use enforcement can stop it."
        ),
        expected={"vulnerable": "allow", "hardened": "deny"},
        attack_label="Replay",
        mode_notes={
            "vulnerable": "Checks the signature but never marks challenges as used",
            "hardened": "Production engine: atomic single-use challenges",
        },
        takeaway=(
            "Both runs use the same genuine signature. The difference is entirely server-side freshness enforcement: "
            "cryptographic validity is necessary but not sufficient."
        ),
    ),
    "tamper": ScenarioInfo(
        id="tamper",
        title="Tamper with a signed response",
        description=(
            "The owner locks the car. An attacker in the middle staples that genuine lock signature onto a fresh "
            "unlock challenge, then intercepts the owner's next unlock and flips one byte of its signature. "
            "Both verifiers rebuild the signed bytes from their own stored challenge, so neither edit verifies."
        ),
        expected={"vulnerable": "deny", "hardened": "deny"},
        attack_label="Tampered response",
        mode_notes={
            "vulnerable": "Replayable, but rebuilds the signed bytes from its stored challenge",
            "hardened": "Production engine: verifies over bytes rebuilt from the challenge row",
        },
        takeaway=(
            "Neither verifier reads the action or nonce from the request: each rebuilds the kg-auth-v1 bytes from "
            "the challenge it issued and stored. A signature over a lock can't authorise an unlock, and a flipped "
            "byte breaks the ECDSA check, so tampering fails even in the replayable verifier."
        ),
    ),
    "substitute": ScenarioInfo(
        id="substitute",
        title="Substitute old signed bytes on a fresh challenge",
        description=(
            "The attacker captured the owner's earlier unlock: the signed message and its signature. Replaying it "
            "on its own challenge fails, because challenges are single use. So when the owner later asks for a lock "
            "challenge, the attacker answers it first with that challenge's ID plus the old unlock bytes and "
            "signature. A verifier that checks the signature over the bytes the client sends, and acts on the "
            "action inside them, unlocks the car."
        ),
        expected={"vulnerable": "allow", "hardened": "deny"},
        attack_label="Substituted message",
        mode_notes={
            "vulnerable": "Single use, but verifies the client's signed bytes and acts on their action",
            "hardened": "Production engine: ignores client bytes and rebuilds them from the challenge row",
        },
        takeaway=(
            "Single use alone isn't enough. The signature is genuine, but over an old unlock message, not over the "
            "lock challenge being consumed. The hardened engine never accepts signed bytes from the client: it "
            "rebuilds them from the stored challenge (its ID, nonce, action and expiry), so the old signature fails "
            "with SIGNATURE_INVALID."
        ),
    ),
    "fob-replay": ScenarioInfo(
        id="fob-replay",
        title="Replay a recorded key-fob press",
        description=(
            "Key fobs have no server challenge: each press signs a counter and an action (kg-fob-v1, D-010). The owner "
            "unlocks and then locks with the fob. An attacker who recorded the earlier unlock press transmits it again, "
            "unchanged."
        ),
        expected={"vulnerable": "allow", "hardened": "deny"},
        attack_label="Fob replay",
        mode_notes={
            "vulnerable": "Checks the fob's signature but keeps no counter",
            "hardened": "Production fob engine: counter must rise, advanced atomically",
        },
        takeaway=(
            "A rolling counter is the fob's replacement for a server challenge: the car remembers the highest counter "
            "it accepted and refuses anything at or below it. The signature is genuine in both runs."
        ),
    ),
    "fob-capture": ScenarioInfo(
        id="fob-capture",
        title="Use a fob press the car never received",
        description=(
            "The owner locks the car and walks away. Later the owner presses unlock out of range, or while an attacker "
            "jams the signal and records it, so the car never receives that press. The attacker transmits the "
            "recorded press afterwards."
        ),
        expected={"vulnerable": "allow", "hardened": "allow"},
        attack_label="Captured unused press",
        mode_notes={
            "vulnerable": "Keeps no counter at all",
            "hardened": "Production fob engine: accepts any fresh counter within the window",
        },
        takeaway=(
            "This is a real limitation of counter schemes, and the hardened engine accepts it by design: the recorded "
            "press carries a counter the car hasn't seen yet, so it looks exactly like a fresh press. Phone and card keys "
            "don't have this weakness, because every challenge is chosen by the car, used once and expires in 30 seconds."
        ),
    ),
    "relay": ScenarioInfo(
        id="relay",
        title="Relay the owner's key card from 40 m away",
        description=(
            "The owner's key card is passive: a tap signs whatever challenge it's shown. Attacker A stands by the car and "
            "requests an unlock challenge. Attacker B stands next to the owner, 40 metres away, and holds a reader near "
            "the owner's bag. The challenge goes to the card, the card signs it, and the signature comes back."
        ),
        expected={"vulnerable": "allow", "hardened": "allow"},
        attack_label="Relayed response",
        mode_notes={
            "vulnerable": "Replayable verifier; signature checks still pass",
            "hardened": "Production engine: fresh, single-use challenge, genuine signature",
        },
        takeaway=(
            "Nothing in the protocol carries distance or timing, so both verifiers see a fresh challenge with a genuine "
            "signature and allow it. A valid signature does not prove the key is near the car. Real systems add distance "
            "bounding or ultra-wideband time-of-flight; KeyGuard doesn't implement or claim either (D-011)."
        ),
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


def _flip_last_byte(signature: str) -> str:
    """A man-in-the-middle edit: XOR the final byte of s (keeps r and s in range, so it's INVALID, not MALFORMED)."""
    raw = bytearray(b64url_decode(signature))
    raw[-1] ^= 0x01
    return b64url_encode(bytes(raw))


_TAMPER_LABELS = (
    "Owner locks the car (signature captured by attacker)",
    "Attacker staples the owner's lock signature onto a fresh unlock challenge",
    "Attacker intercepts the owner's next unlock and flips one signature byte",
)


def _attack_outcome(run: ModeRun) -> None:
    """The attack succeeds if any attacker step was allowed; otherwise report the last attacker denial."""
    attacks = [s for s in run.steps if s.actor == "attacker"]
    hit = next((s for s in attacks if s.decision == "allow"), attacks[-1])
    run.attack_decision, run.attack_reason = hit.decision, hit.reason
    run.final_lock_state = run.steps[-1].lock_state


def _tamper_vulnerable(now: int) -> ModeRun:
    run = ModeRun("vulnerable")
    v = VulnerableVerifier()
    key = SimulatedClientKey()
    vehicle_id, key_id = "veh_" + "V" * 22, "key_" + "V" * 22

    def issue(action: str) -> SignedFields:
        return v.issue(vehicle_id=vehicle_id, key_id=key_id, spki_b64url=key.spki_b64url, action=action, now=now)

    lock = issue("lock")
    lock_sig = _sign(key, lock)
    d, r = v.verify(challenge_id=lock.challenge_id, signature=lock_sig)
    run.steps.append(Step(1, "owner", _TAMPER_LABELS[0], d, r, v.lock_state))

    forged_unlock = issue("unlock")
    d, r = v.verify(challenge_id=forged_unlock.challenge_id, signature=lock_sig)
    run.steps.append(Step(2, "attacker", _TAMPER_LABELS[1], d, r, v.lock_state))

    owner_unlock = issue("unlock")
    d, r = v.verify(challenge_id=owner_unlock.challenge_id, signature=_flip_last_byte(_sign(key, owner_unlock)))
    run.steps.append(Step(3, "attacker", _TAMPER_LABELS[2], d, r, v.lock_state))
    _attack_outcome(run)
    return run


def _tamper_hardened(now: int) -> ModeRun:
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

            lock = issue("lock")
            lock_sig = _sign(key, lock)
            d = submit(lock.challenge_id, lock_sig)
            run.steps.append(Step(1, "owner", _TAMPER_LABELS[0], d.decision, d.reason, d.lock_state))

            forged_unlock = issue("unlock")
            d = submit(forged_unlock.challenge_id, lock_sig)
            run.steps.append(Step(2, "attacker", _TAMPER_LABELS[1], d.decision, d.reason, d.lock_state))

            owner_unlock = issue("unlock")
            d = submit(owner_unlock.challenge_id, _flip_last_byte(_sign(key, owner_unlock)))
            run.steps.append(Step(3, "attacker", _TAMPER_LABELS[2], d.decision, d.reason, d.lock_state))
            _attack_outcome(run)
        finally:
            engine.dispose()
    return run


_SUBSTITUTE_LABELS = (
    "Owner unlocks (signed message and signature captured by attacker)",
    "Owner locks and walks away",
    "Attacker replays the captured unlock on its own challenge",
    "Owner requests a new lock challenge; attacker answers it first with the old unlock bytes and signature",
)


def _substitute_vulnerable(now: int) -> ModeRun:
    run = ModeRun("vulnerable")
    v = ClientBytesVerifier()
    key = SimulatedClientKey()
    vehicle_id, key_id = "veh_" + "V" * 22, "key_" + "V" * 22

    def issue(action: str) -> SignedFields:
        return v.issue(vehicle_id=vehicle_id, key_id=key_id, spki_b64url=key.spki_b64url, action=action, now=now)

    def respond(f: SignedFields) -> tuple[str, str]:
        """What a client sends to this verifier: the signed bytes and the signature over them."""
        return b64url_encode(encode_signed_message(f)), _sign(key, f)

    unlock = issue("unlock")
    captured_msg, captured_sig = respond(unlock)
    d, r = v.verify(challenge_id=unlock.challenge_id, signed_message=captured_msg, signature=captured_sig)
    run.steps.append(Step(1, "owner", _SUBSTITUTE_LABELS[0], d, r, v.lock_state))

    lock = issue("lock")
    lock_msg, lock_sig = respond(lock)
    d, r = v.verify(challenge_id=lock.challenge_id, signed_message=lock_msg, signature=lock_sig)
    run.steps.append(Step(2, "owner", _SUBSTITUTE_LABELS[1], d, r, v.lock_state))

    d, r = v.verify(challenge_id=unlock.challenge_id, signed_message=captured_msg, signature=captured_sig)
    run.steps.append(Step(3, "attacker", _SUBSTITUTE_LABELS[2], d, r, v.lock_state))

    fresh_lock = issue("lock")
    d, r = v.verify(challenge_id=fresh_lock.challenge_id, signed_message=captured_msg, signature=captured_sig)
    run.steps.append(Step(4, "attacker", _SUBSTITUTE_LABELS[3], d, r, v.lock_state))
    _attack_outcome(run)
    return run


@contextmanager
def _hardened_sandbox(now: int, credential_type: str = "phone") -> Iterator[tuple]:
    """A throwaway SQLite lab with one enrolled owner key; yields (key, issue, submit) bound to it."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = make_engine(f"sqlite:///{Path(tmp) / 'scenario.db'}")
        try:
            key = SimulatedClientKey()
            with engine.begin() as conn:
                lab = create_lab(conn, now=now)
                key_id = enroll_key(
                    conn, lab_id=lab.lab_id, vehicle_id=lab.vehicle_id, spki_b64url=key.spki_b64url, label="owner",
                    now=now, credential_type=credential_type,
                )

            def issue(action: str) -> SignedFields:
                with engine.begin() as conn:
                    c = issue_challenge(conn, lab_id=lab.lab_id, vehicle_id=lab.vehicle_id, key_id=key_id, action=action, now=now)
                return c.signed_fields()

            def submit(chl_id: str, sig: str):
                return authenticate(engine, lab_id=lab.lab_id, challenge_id=chl_id, key_id=key_id, signature=sig, clock=lambda: now)

            yield key, issue, submit
        finally:
            engine.dispose()


def _substitute_hardened(now: int) -> ModeRun:
    run = ModeRun("hardened")
    with _hardened_sandbox(now) as (key, issue, submit):
        unlock = issue("unlock")
        # The attacker captures the same pair as in the vulnerable run. The production API has no field for
        # signed bytes, so only the signature travels; the engine rebuilds the message from the challenge row.
        captured_sig = _sign(key, unlock)
        d = submit(unlock.challenge_id, captured_sig)
        run.steps.append(Step(1, "owner", _SUBSTITUTE_LABELS[0], d.decision, d.reason, d.lock_state))

        lock = issue("lock")
        d = submit(lock.challenge_id, _sign(key, lock))
        run.steps.append(Step(2, "owner", _SUBSTITUTE_LABELS[1], d.decision, d.reason, d.lock_state))

        d = submit(unlock.challenge_id, captured_sig)
        run.steps.append(Step(3, "attacker", _SUBSTITUTE_LABELS[2], d.decision, d.reason, d.lock_state))

        fresh_lock = issue("lock")
        d = submit(fresh_lock.challenge_id, captured_sig)
        run.steps.append(Step(4, "attacker", _SUBSTITUTE_LABELS[3], d.decision, d.reason, d.lock_state))
        _attack_outcome(run)
    return run


# --- Key fob scenarios (D-010) ---------------------------------------------------------------------


def _fob_sign(key: SimulatedClientKey, vehicle_id: str, key_id: str, counter: int, action: str) -> str:
    return key.sign_p1363(encode_fob_message(FobFields(vehicle_id, key_id, counter, action)))


@contextmanager
def _fob_sandbox(now: int) -> Iterator[tuple]:
    """A throwaway lab with one enrolled fob; yields (sign, press) for the real production fob engine."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = make_engine(f"sqlite:///{Path(tmp) / 'scenario.db'}")
        try:
            key = SimulatedClientKey()
            with engine.begin() as conn:
                lab = create_lab(conn, now=now)
                key_id = enroll_key(conn, lab_id=lab.lab_id, vehicle_id=lab.vehicle_id, spki_b64url=key.spki_b64url,
                                    label="owner fob", now=now, credential_type="fob")

            def sign(counter: int, action: str) -> str:
                return _fob_sign(key, lab.vehicle_id, key_id, counter, action)

            def press(counter: int, action: str, signature: str):
                return press_fob(engine, lab_id=lab.lab_id, key_id=key_id, vehicle_id=lab.vehicle_id, action=action,
                                 counter=counter, signature=signature, clock=lambda: now)

            yield sign, press
        finally:
            engine.dispose()


def _counterless(now: int) -> tuple[CounterlessFobReceiver, Callable[[int, str], str]]:
    key = SimulatedClientKey()
    vehicle_id, key_id = "veh_" + "V" * 22, "key_" + "V" * 22
    rx = CounterlessFobReceiver(vehicle_id=vehicle_id, key_id=key_id, spki_b64url=key.spki_b64url)
    return rx, lambda counter, action: _fob_sign(key, vehicle_id, key_id, counter, action)


_FOB_REPLAY_LABELS = (
    "Owner presses unlock (counter 1); attacker records it",
    "Owner presses lock (counter 2) and walks away",
    "Attacker transmits the recorded unlock press (counter 1)",
)


def _fob_replay_vulnerable(now: int) -> ModeRun:
    run = ModeRun("vulnerable")
    rx, sign = _counterless(now)
    recorded = sign(1, "unlock")
    d, r = rx.press(counter=1, action="unlock", signature=recorded)
    run.steps.append(Step(1, "owner", _FOB_REPLAY_LABELS[0], d, r, rx.lock_state))
    d, r = rx.press(counter=2, action="lock", signature=sign(2, "lock"))
    run.steps.append(Step(2, "owner", _FOB_REPLAY_LABELS[1], d, r, rx.lock_state))
    d, r = rx.press(counter=1, action="unlock", signature=recorded)
    run.steps.append(Step(3, "attacker", _FOB_REPLAY_LABELS[2], d, r, rx.lock_state))
    _attack_outcome(run)
    return run


def _fob_replay_hardened(now: int) -> ModeRun:
    run = ModeRun("hardened")
    with _fob_sandbox(now) as (sign, press):
        recorded = sign(1, "unlock")
        d = press(1, "unlock", recorded)
        run.steps.append(Step(1, "owner", _FOB_REPLAY_LABELS[0], d.decision, d.reason, d.lock_state))
        d = press(2, "lock", sign(2, "lock"))
        run.steps.append(Step(2, "owner", _FOB_REPLAY_LABELS[1], d.decision, d.reason, d.lock_state))
        d = press(1, "unlock", recorded)
        run.steps.append(Step(3, "attacker", _FOB_REPLAY_LABELS[2], d.decision, d.reason, d.lock_state))
        _attack_outcome(run)
    return run


_FOB_CAPTURE_LABELS = (
    "Owner presses unlock (counter 1)",
    "Owner presses lock (counter 2) and walks away",
    "Attacker transmits a press it recorded while jamming the car (counter 3, never received by the car)",
)


def _fob_capture_vulnerable(now: int) -> ModeRun:
    run = ModeRun("vulnerable")
    rx, sign = _counterless(now)
    d, r = rx.press(counter=1, action="unlock", signature=sign(1, "unlock"))
    run.steps.append(Step(1, "owner", _FOB_CAPTURE_LABELS[0], d, r, rx.lock_state))
    d, r = rx.press(counter=2, action="lock", signature=sign(2, "lock"))
    run.steps.append(Step(2, "owner", _FOB_CAPTURE_LABELS[1], d, r, rx.lock_state))
    captured = sign(3, "unlock")  # the jammed press: the receiver never saw it
    d, r = rx.press(counter=3, action="unlock", signature=captured)
    run.steps.append(Step(3, "attacker", _FOB_CAPTURE_LABELS[2], d, r, rx.lock_state))
    _attack_outcome(run)
    return run


def _fob_capture_hardened(now: int) -> ModeRun:
    run = ModeRun("hardened")
    with _fob_sandbox(now) as (sign, press):
        d = press(1, "unlock", sign(1, "unlock"))
        run.steps.append(Step(1, "owner", _FOB_CAPTURE_LABELS[0], d.decision, d.reason, d.lock_state))
        d = press(2, "lock", sign(2, "lock"))
        run.steps.append(Step(2, "owner", _FOB_CAPTURE_LABELS[1], d.decision, d.reason, d.lock_state))
        captured = sign(3, "unlock")
        d = press(3, "unlock", captured)
        run.steps.append(Step(3, "attacker", _FOB_CAPTURE_LABELS[2], d.decision, d.reason, d.lock_state))
        _attack_outcome(run)
    return run


# --- Relay (D-011) --------------------------------------------------------------------------------

_RELAY_LABELS = (
    "Owner taps the card to lock and walks 40 m away",
    "Attacker A requests an unlock challenge at the car; attacker B relays it to the owner's card, "
    "which signs it; the signature is relayed back",
)


def _relay_vulnerable(now: int) -> ModeRun:
    run = ModeRun("vulnerable")
    v = VulnerableVerifier()
    card = SimulatedClientKey()
    vehicle_id, key_id = "veh_" + "V" * 22, "key_" + "V" * 22

    def issue(action: str) -> SignedFields:
        return v.issue(vehicle_id=vehicle_id, key_id=key_id, spki_b64url=card.spki_b64url, action=action, now=now)

    lock = issue("lock")
    d, r = v.verify(challenge_id=lock.challenge_id, signature=_sign(card, lock))
    run.steps.append(Step(1, "owner", _RELAY_LABELS[0], d, r, v.lock_state))
    relayed = issue("unlock")
    d, r = v.verify(challenge_id=relayed.challenge_id, signature=_sign(card, relayed))  # the passive card signs it
    run.steps.append(Step(2, "attacker", _RELAY_LABELS[1], d, r, v.lock_state))
    _attack_outcome(run)
    return run


def _relay_hardened(now: int) -> ModeRun:
    run = ModeRun("hardened")
    with _hardened_sandbox(now, credential_type="card") as (card, issue, submit):
        lock = issue("lock")
        d = submit(lock.challenge_id, _sign(card, lock))
        run.steps.append(Step(1, "owner", _RELAY_LABELS[0], d.decision, d.reason, d.lock_state))
        relayed = issue("unlock")
        d = submit(relayed.challenge_id, _sign(card, relayed))
        run.steps.append(Step(2, "attacker", _RELAY_LABELS[1], d.decision, d.reason, d.lock_state))
        _attack_outcome(run)
    return run


_RUNNERS = {
    "replay": (_replay_vulnerable, _replay_hardened),
    "tamper": (_tamper_vulnerable, _tamper_hardened),
    "substitute": (_substitute_vulnerable, _substitute_hardened),
    "fob-replay": (_fob_replay_vulnerable, _fob_replay_hardened),
    "fob-capture": (_fob_capture_vulnerable, _fob_capture_hardened),
    "relay": (_relay_vulnerable, _relay_hardened),
}


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
        "attack_label": info.attack_label,
        "mode_notes": info.mode_notes,
        "takeaway": info.takeaway,
        "actual": actual,
        "matches_expected": actual == info.expected,
        "runs": [asdict(r) for r in runs],
        "duration_ms": round((time.perf_counter() - started) * 1000),
    }
