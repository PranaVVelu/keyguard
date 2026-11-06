"""Mandatory hardened test matrix (spec §7), end-to-end through the HTTP API.

Each test is tagged with its matrix row in the docstring; docs/SECURITY_TESTS.md maps them.
The client side is simulated in Python exactly as the browser does it: P-256 key,
canonical kg-auth-v1 bytes built from the challenge response, P1363 signature.
"""

from __future__ import annotations

import threading

import pytest
from sqlalchemy import insert, select, update

from app.models.tables import digital_keys, security_events, vehicles
from app.security.authenticate import authenticate
from app.security.challenges import CHALLENGE_TTL_SECONDS, MAX_OPEN_CHALLENGES_PER_LAB
from app.security.encoding import b64url_decode, b64url_encode, new_id
from app.security.protocol import SignedFields, encode_signed_message
from conftest import NOW
from helpers import SimulatedClientKey


class Lab:
    """Test driver for one lab: enroll, request challenges, sign, authenticate."""

    def __init__(self, client, new_lab):
        self.client = client
        self.id = new_lab["lab_id"]
        self.token = new_lab["lab_token"]
        self.headers = new_lab["headers"]
        self.vehicle_id = new_lab["vehicle_id"]

    def enroll(self, key: SimulatedClientKey | None = None, vehicle_id: str | None = None) -> tuple[str, SimulatedClientKey]:
        key = key or SimulatedClientKey()
        resp = self.client.post(
            f"/api/labs/{self.id}/keys",
            json={"vehicle_id": vehicle_id or self.vehicle_id, "public_key": key.spki_b64url, "label": "k"},
            headers=self.headers,
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["id"], key

    def challenge(self, key_id: str, action: str = "unlock", vehicle_id: str | None = None):
        return self.client.post(
            f"/api/labs/{self.id}/challenges",
            json={"vehicle_id": vehicle_id or self.vehicle_id, "key_id": key_id, "action": action},
            headers=self.headers,
        )

    def authenticate(self, challenge_id: str, key_id: str, signature: str, headers=None):
        return self.client.post(
            f"/api/labs/{self.id}/authenticate",
            json={"challenge_id": challenge_id, "key_id": key_id, "signature": signature},
            headers=headers or self.headers,
        )

    def lock_state(self) -> str:
        vs = self.client.get(f"/api/labs/{self.id}/vehicles", headers=self.headers).json()["vehicles"]
        return next(v for v in vs if v["id"] == self.vehicle_id)["lock_state"]


def fields_from(chl: dict, **override) -> SignedFields:
    f = {k: chl[k] for k in ("vehicle_id", "key_id", "challenge_id", "nonce", "action", "expires_at")}
    return SignedFields(**{**f, **override})


def sign(key: SimulatedClientKey, chl: dict, **override) -> str:
    return key.sign_p1363(encode_signed_message(fields_from(chl, **override)))


@pytest.fixture
def lab(client, new_lab) -> Lab:
    return Lab(client, new_lab)


@pytest.fixture
def enrolled(lab):
    key_id, key = lab.enroll()
    return lab, key_id, key


def _issue(lab, key_id, action="unlock"):
    resp = lab.challenge(key_id, action)
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- Row 1: active key + fresh challenge → Allow -----------------------------------------


def test_row01_active_key_fresh_challenge_allows_and_changes_state(enrolled):
    """Matrix row 1: Active key + fresh challenge → Allow."""
    lab, key_id, key = enrolled
    assert lab.lock_state() == "locked"

    chl = _issue(lab, key_id, "unlock")
    assert chl["protocol_version"] == "kg-auth-v1"
    assert chl["expires_at"] == NOW + CHALLENGE_TTL_SECONDS
    assert len(b64url_decode(chl["nonce"])) == 32

    resp = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl))
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["reason"] is None
    assert body["lock_state"] == "unlocked"
    assert [s["status"] for s in body["trace"]] == ["pass"] * 6
    assert lab.lock_state() == "unlocked"

    chl = _issue(lab, key_id, "lock")
    assert lab.authenticate(chl["challenge_id"], key_id, sign(key, chl)).json()["decision"] == "allow"
    assert lab.lock_state() == "locked"


# --- Row 2: incorrect signature → Deny ------------------------------------------------------


@pytest.mark.parametrize(
    "make_sig, reason",
    [
        (lambda key, chl: SimulatedClientKey().sign_p1363(encode_signed_message(fields_from(chl))), "SIGNATURE_INVALID"),
        (
            lambda key, chl: b64url_encode(
                (lambda b: b[:-1] + bytes([b[-1] ^ 1]))(b64url_decode(sign(key, chl)))
            ),
            "SIGNATURE_INVALID",
        ),
        (lambda key, chl: sign(key, chl, nonce=b64url_encode(bytes(32))), "SIGNATURE_INVALID"),
        (lambda key, chl: sign(key, chl)[:-4], "SIGNATURE_MALFORMED"),
        (lambda key, chl: b64url_encode(bytes(64)), "SIGNATURE_MALFORMED"),
        (lambda key, chl: "not*base64", "SIGNATURE_MALFORMED"),
    ],
    ids=["other-key", "bit-flip", "wrong-nonce", "truncated", "all-zero", "bad-charset"],
)
def test_row02_incorrect_signature_denies(enrolled, make_sig, reason):
    """Matrix row 2: Incorrect signature → Deny."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    body = lab.authenticate(chl["challenge_id"], key_id, make_sig(key, chl)).json()
    assert body["decision"] == "deny"
    assert body["reason"] == reason
    assert body["lock_state"] == "locked"
    assert lab.lock_state() == "locked"
    failed = [s for s in body["trace"] if s["status"] == "fail"]
    assert failed == [{"step": "signature_valid", "status": "fail", "detail": reason}]


# --- Row 3: revoked key → Deny ----------------------------------------------------------------


def _revoke(lab, key_id):
    resp = lab.client.post(f"/api/labs/{lab.id}/keys/{key_id}/revoke", headers=lab.headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "revoked"


def test_row03_key_revoked_after_challenge_issued_is_denied(enrolled):
    """Matrix row 3: Revoked key → Deny, even with a valid signature over a challenge issued while it was active."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    _revoke(lab, key_id)
    body = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl)).json()
    assert (body["decision"], body["reason"]) == ("deny", "KEY_REVOKED")
    assert lab.lock_state() == "locked"


def test_row03_revoked_key_cannot_get_a_challenge(enrolled):
    lab, key_id, _ = enrolled
    _revoke(lab, key_id)
    resp = lab.challenge(key_id)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "KEY_REVOKED"


def test_row03_other_active_key_still_works_after_revocation(lab):
    """Spec revocation journey: two keys, revoke one, the other still authenticates."""
    revoked_id, revoked_key = lab.enroll()
    active_id, active_key = lab.enroll()
    chl_r = _issue(lab, revoked_id)
    _revoke(lab, revoked_id)
    assert lab.authenticate(chl_r["challenge_id"], revoked_id, sign(revoked_key, chl_r)).json()["decision"] == "deny"
    chl_a = _issue(lab, active_id)
    assert lab.authenticate(chl_a["challenge_id"], active_id, sign(active_key, chl_a)).json()["decision"] == "allow"


# --- Row 4: expired challenge → Deny --------------------------------------------------------


@pytest.mark.parametrize("delay", [CHALLENGE_TTL_SECONDS, CHALLENGE_TTL_SECONDS + 1, 3600])
def test_row04_expired_challenge_denies(enrolled, clock, delay):
    """Matrix row 4: Expired challenge → Deny (expires_at is exclusive)."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    clock.t = NOW + delay
    body = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl)).json()
    assert (body["decision"], body["reason"]) == ("deny", "CHALLENGE_EXPIRED")
    assert lab.lock_state() == "locked"


def test_row04_last_second_before_expiry_still_allows(enrolled, clock):
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    clock.t = NOW + CHALLENGE_TTL_SECONDS - 1
    assert lab.authenticate(chl["challenge_id"], key_id, sign(key, chl)).json()["decision"] == "allow"


# --- Row 5: consumed challenge replay → Deny ----------------------------------------------


def test_row05_replay_of_accepted_response_denies(enrolled):
    """Matrix row 5: Consumed challenge replay → Deny. The replayed unlock must not re-unlock a locked car."""
    lab, key_id, key = enrolled
    unlock = _issue(lab, key_id, "unlock")
    captured = (unlock["challenge_id"], key_id, sign(key, unlock))
    assert lab.authenticate(*captured).json()["decision"] == "allow"

    lock = _issue(lab, key_id, "lock")
    assert lab.authenticate(lock["challenge_id"], key_id, sign(key, lock)).json()["decision"] == "allow"
    assert lab.lock_state() == "locked"

    replay = lab.authenticate(*captured).json()
    assert (replay["decision"], replay["reason"]) == ("deny", "CHALLENGE_CONSUMED")
    assert lab.lock_state() == "locked"


def test_row05_failed_attempt_burns_challenge(enrolled):
    """O-2: one attempt per challenge. A bad signature spends it, so a later valid one is refused."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    assert lab.authenticate(chl["challenge_id"], key_id, b64url_encode(bytes(64))).json()["decision"] == "deny"
    body = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl)).json()
    assert (body["decision"], body["reason"]) == ("deny", "CHALLENGE_CONSUMED")


# --- Row 6: wrong vehicle → Deny ------------------------------------------------------------


def _add_vehicle(lab) -> str:
    vid = new_id("veh")
    with lab.client.app.state.engine.begin() as conn:
        conn.execute(insert(vehicles).values(id=vid, lab_id=lab.id, name="Second", lock_state="locked", created_at=NOW))
    return vid


def test_row06_signature_bound_to_other_vehicle_denies(enrolled):
    """Matrix row 6: Wrong vehicle → Deny. Signing a different vehicle_id doesn't match the server's bytes."""
    lab, key_id, key = enrolled
    other_vehicle = _add_vehicle(lab)
    chl = _issue(lab, key_id)
    body = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl, vehicle_id=other_vehicle)).json()
    assert (body["decision"], body["reason"]) == ("deny", "SIGNATURE_INVALID")


def test_row06_key_cannot_get_challenge_for_unbound_vehicle(enrolled):
    lab, key_id, _ = enrolled
    other_vehicle = _add_vehicle(lab)
    resp = lab.challenge(key_id, vehicle_id=other_vehicle)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VEHICLE_MISMATCH"


def test_row06_key_rebound_after_issue_is_denied(enrolled):
    """Authorization is re-checked at authenticate time, not trusted from issuance."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    other_vehicle = _add_vehicle(lab)
    with lab.client.app.state.engine.begin() as conn:
        conn.execute(update(digital_keys).where(digital_keys.c.id == key_id).values(vehicle_id=other_vehicle))
    body = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl)).json()
    assert (body["decision"], body["reason"]) == ("deny", "VEHICLE_MISMATCH")


# --- Row 7: wrong requested action → Deny ---------------------------------------------------


def test_row07_unlock_signature_over_lock_challenge_denies(enrolled):
    """Matrix row 7: Wrong action → Deny. Client signs 'unlock' but the server issued 'lock'."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id, "lock")
    body = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl, action="unlock")).json()
    assert (body["decision"], body["reason"]) == ("deny", "SIGNATURE_INVALID")


def test_row07_lock_response_cannot_be_reused_for_unlock_challenge(enrolled):
    lab, key_id, key = enrolled
    lock_chl = _issue(lab, key_id, "lock")
    unlock_chl = _issue(lab, key_id, "unlock")
    body = lab.authenticate(unlock_chl["challenge_id"], key_id, sign(key, lock_chl)).json()
    assert (body["decision"], body["reason"]) == ("deny", "SIGNATURE_INVALID")
    assert lab.lock_state() == "locked"


# --- Row 8: two concurrent submissions → at most one succeeds -------------------------------


@pytest.mark.parametrize("round_", range(5))
def test_row08_concurrent_submissions_at_most_one_allows(enrolled, round_):
    """Matrix row 8: concurrent identical valid submissions through the full engine → exactly one allow."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    sig = sign(key, chl)
    engine, clock = lab.client.app.state.engine, lab.client.app.state.clock
    workers = 16
    barrier = threading.Barrier(workers)
    decisions, errors = [], []
    lock = threading.Lock()

    def attempt():
        try:
            barrier.wait()
            d = authenticate(engine, lab_id=lab.id, challenge_id=chl["challenge_id"], key_id=key_id, signature=sig, clock=clock)
            with lock:
                decisions.append((d.decision, d.reason))
        except BaseException as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len(decisions) == workers
    assert decisions.count(("allow", None)) == 1
    assert decisions.count(("deny", "CHALLENGE_CONSUMED")) == workers - 1
    assert lab.lock_state() == "unlocked"


# --- Row 9: unknown key → Deny --------------------------------------------------------------


def test_row09_unknown_key_cannot_get_challenge(lab):
    """Matrix row 9: Unknown key → Deny."""
    resp = lab.challenge(new_id("key"))
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "KEY_UNKNOWN"


def test_row09_authenticate_with_key_other_than_challenges_denies(lab):
    owner_id, _ = lab.enroll()
    intruder_id, intruder = lab.enroll()
    chl = _issue(lab, owner_id)
    # Intruder signs the exact challenge fields, but under its own key ID.
    body = lab.authenticate(chl["challenge_id"], intruder_id, sign(intruder, chl, key_id=intruder_id)).json()
    assert (body["decision"], body["reason"]) == ("deny", "KEY_MISMATCH")
    assert lab.lock_state() == "locked"


def test_row09_unknown_key_id_on_authenticate_denies(enrolled):
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    body = lab.authenticate(chl["challenge_id"], new_id("key"), sign(key, chl)).json()
    assert (body["decision"], body["reason"]) == ("deny", "KEY_MISMATCH")


# --- Row 10: malformed payload → reject safely ----------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"challenge_id": "chl_x", "key_id": "key_x", "signature": "AA"},
        {"challenge_id": None, "key_id": None, "signature": None},
        {"challenge_id": 1, "key_id": 2, "signature": 3},
        {"challenge_id": "chl_" + "A" * 22, "key_id": "key_" + "A" * 22, "signature": "A" * 5000},
        {"challenge_id": "chl_" + "A" * 22, "key_id": "key_" + "A" * 22, "signature": "AA", "decision": "allow"},
        ["not", "an", "object"],
    ],
    ids=["empty", "bad-ids", "nulls", "numbers", "oversized-sig", "client-asserted-decision", "array"],
)
def test_row10_malformed_authenticate_payload_rejected_safely(enrolled, payload):
    """Matrix row 10: Malformed payload → 422 REQUEST_INVALID, no engine call, no state change."""
    lab, _, _ = enrolled
    resp = lab.client.post(f"/api/labs/{lab.id}/authenticate", json=payload, headers=lab.headers)
    assert resp.status_code == 422
    assert resp.json() == {"error": {"code": "REQUEST_INVALID", "message": "Request failed validation"}}
    assert lab.lock_state() == "locked"


def test_row10_non_json_body_rejected(enrolled):
    lab, _, _ = enrolled
    resp = lab.client.post(
        f"/api/labs/{lab.id}/authenticate", content=b"\x00\xff garbage", headers={**lab.headers, "Content-Type": "application/json"}
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("action", ["open_trunk", "UNLOCK", "", None])
def test_row10_malformed_challenge_request_rejected(enrolled, action):
    lab, key_id, _ = enrolled
    resp = lab.client.post(
        f"/api/labs/{lab.id}/challenges",
        json={"vehicle_id": lab.vehicle_id, "key_id": key_id, "action": action},
        headers=lab.headers,
    )
    assert resp.status_code == 422


# --- Row 11: cross-lab request → Deny -------------------------------------------------------


def test_row11_other_labs_token_cannot_authenticate_here(client, enrolled):
    """Matrix row 11: Cross-lab request → Deny."""
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    other = client.post("/api/labs").json()
    resp = lab.authenticate(chl["challenge_id"], key_id, sign(key, chl), headers={"Authorization": f"Bearer {other['lab_token']}"})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "LAB_NOT_FOUND"
    assert lab.lock_state() == "locked"
    # And the challenge was not burned by the rejected cross-lab call.
    assert lab.authenticate(chl["challenge_id"], key_id, sign(key, chl)).json()["decision"] == "allow"


def test_row11_challenge_from_another_lab_is_not_found(client, enrolled):
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    other = client.post("/api/labs").json()
    other_headers = {"Authorization": f"Bearer {other['lab_token']}"}
    resp = client.post(
        f"/api/labs/{other['lab_id']}/authenticate",
        json={"challenge_id": chl["challenge_id"], "key_id": key_id, "signature": sign(key, chl)},
        headers=other_headers,
    )
    body = resp.json()
    assert (body["decision"], body["reason"]) == ("deny", "CHALLENGE_NOT_FOUND")
    assert lab.lock_state() == "locked"


def test_row11_cannot_request_challenge_for_another_labs_key(client, enrolled):
    lab, key_id, _ = enrolled
    other = client.post("/api/labs").json()
    other_headers = {"Authorization": f"Bearer {other['lab_token']}"}
    other_vehicle = client.get(f"/api/labs/{other['lab_id']}/vehicles", headers=other_headers).json()["vehicles"][0]["id"]
    resp = client.post(
        f"/api/labs/{other['lab_id']}/challenges",
        json={"vehicle_id": other_vehicle, "key_id": key_id, "action": "unlock"},
        headers=other_headers,
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "KEY_UNKNOWN"


# --- Supporting properties ------------------------------------------------------------------


def test_open_challenge_cap(enrolled):
    lab, key_id, _ = enrolled
    for _ in range(MAX_OPEN_CHALLENGES_PER_LAB):
        assert lab.challenge(key_id).status_code == 201
    resp = lab.challenge(key_id)
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "CHALLENGE_LIMIT_REACHED"


def test_decisions_are_logged_without_signatures(enrolled):
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    sig = sign(key, chl)
    lab.authenticate(chl["challenge_id"], key_id, sig)
    lab.authenticate(chl["challenge_id"], key_id, sig)  # replay
    with lab.client.app.state.engine.connect() as conn:
        rows = conn.execute(
            select(security_events.c.event_type, security_events.c.outcome, security_events.c.reason, security_events.c.duration_ms)
            .where(security_events.c.event_type == "authenticate_unlock")
        ).all()
        dump = " ".join(str(v) for r in conn.execute(select(security_events)).all() for v in r)
    assert sorted((r.outcome, r.reason) for r in rows) == [("allow", None), ("deny", "CHALLENGE_CONSUMED")]
    assert all(r.duration_ms is not None and r.duration_ms >= 0 for r in rows)
    assert sig not in dump and chl["nonce"] not in dump and lab.token not in dump


def test_response_trace_contains_no_secrets(enrolled):
    lab, key_id, key = enrolled
    chl = _issue(lab, key_id)
    sig = sign(key, chl)
    text = lab.authenticate(chl["challenge_id"], key_id, sig).text
    assert sig not in text and chl["nonce"] not in text and key.spki_b64url not in text
