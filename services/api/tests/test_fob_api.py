"""Key fob credentials (F10, D-010): kg-fob-v1 rolling counter, end to end through the API and engine."""

from __future__ import annotations

import threading

import pytest
from sqlalchemy import insert, select

from app.models.tables import challenges, digital_keys
from app.security.authenticate import authenticate
from app.security.encoding import b64url_encode, new_id
from app.security.fob import FOB_WINDOW, press_fob
from app.security.protocol import (
    DOMAIN_TAG,
    DOMAIN_TAG_FOB,
    FobFields,
    ProtocolError,
    encode_fob_message,
)
from conftest import NOW
from helpers import SimulatedClientKey
from test_authenticate_api import Lab, sign


class Fob:
    """Test stand-in for the browser fob: a key plus a counter it increments before every press."""

    def __init__(self, lab: Lab, key_id: str, key: SimulatedClientKey, vehicle_id: str):
        self.lab, self.key_id, self.key, self.vehicle_id = lab, key_id, key, vehicle_id
        self.counter = 0

    def signature(self, counter: int, action: str, *, vehicle_id: str | None = None, key_id: str | None = None) -> str:
        fields = FobFields(vehicle_id or self.vehicle_id, key_id or self.key_id, counter, action)
        return self.key.sign_p1363(encode_fob_message(fields))

    def press(self, action: str = "unlock", *, counter: int | None = None, signature: str | None = None, **body):
        if counter is None:
            self.counter += 1
            counter = self.counter
        payload = {
            "vehicle_id": self.vehicle_id,
            "key_id": self.key_id,
            "action": action,
            "counter": counter,
            "signature": signature or self.signature(counter, action),
            **body,
        }
        return self.lab.client.post(f"/api/labs/{self.lab.id}/fob", json=payload, headers=self.lab.headers)


def _enroll(lab: Lab, credential_type: str, vehicle_id: str | None = None) -> tuple[str, SimulatedClientKey]:
    key = SimulatedClientKey()
    resp = lab.client.post(
        f"/api/labs/{lab.id}/keys",
        json={
            "vehicle_id": vehicle_id or lab.vehicle_id,
            "public_key": key.spki_b64url,
            "label": credential_type,
            "credential_type": credential_type,
        },
        headers=lab.headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"], key


@pytest.fixture
def lab(client, new_lab) -> Lab:
    return Lab(client, new_lab)


@pytest.fixture
def fob(lab) -> Fob:
    key_id, key = _enroll(lab, "fob")
    return Fob(lab, key_id, key, lab.vehicle_id)


def _last_counter(lab: Lab, key_id: str) -> int:
    keys = lab.client.get(f"/api/labs/{lab.id}/keys", headers=lab.headers).json()["keys"]
    return next(k for k in keys if k["id"] == key_id)["last_counter"]


# --- Encoding --------------------------------------------------------------------------------------


def test_fob_encoding_is_framed_and_domain_separated():
    msg = encode_fob_message(FobFields("veh_" + "A" * 22, "key_" + "B" * 22, 7, "unlock"))
    assert msg.startswith(DOMAIN_TAG_FOB)
    assert DOMAIN_TAG_FOB != DOMAIN_TAG and not msg.startswith(DOMAIN_TAG)
    body = msg[len(DOMAIN_TAG_FOB):]
    fields, i = [], 0
    while i < len(body):
        n = int.from_bytes(body[i : i + 4], "big")
        fields.append(body[i + 4 : i + 4 + n].decode())
        i += 4 + n
    assert fields == ["kg-fob-v1", "veh_" + "A" * 22, "key_" + "B" * 22, "7", "unlock"]


@pytest.mark.parametrize("counter", [0, -1, 2**53, True, "1"])
def test_fob_encoding_rejects_bad_counters(counter):
    with pytest.raises(ProtocolError, match="COUNTER_INVALID"):
        encode_fob_message(FobFields("veh_" + "A" * 22, "key_" + "B" * 22, counter, "unlock"))


# --- Enrollment ------------------------------------------------------------------------------------


def test_credential_types_are_listed(lab):
    ids = {t: _enroll(lab, t)[0] for t in ("phone", "card", "fob")}
    keys = {k["id"]: k for k in lab.client.get(f"/api/labs/{lab.id}/keys", headers=lab.headers).json()["keys"]}
    for t, key_id in ids.items():
        assert keys[key_id]["credential_type"] == t
        assert keys[key_id]["last_counter"] == 0


def test_enrollment_defaults_to_phone_and_rejects_unknown_types(lab):
    key = SimulatedClientKey()
    body = {"vehicle_id": lab.vehicle_id, "public_key": key.spki_b64url, "label": "x"}
    assert lab.client.post(f"/api/labs/{lab.id}/keys", json=body, headers=lab.headers).json()["credential_type"] == "phone"
    bad = lab.client.post(
        f"/api/labs/{lab.id}/keys",
        json={**body, "public_key": SimulatedClientKey().spki_b64url, "credential_type": "nfc-tag"},
        headers=lab.headers,
    )
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "REQUEST_INVALID"


# --- Happy path and counter rules ------------------------------------------------------------------


def test_press_allows_and_advances_the_counter(fob):
    d = fob.press("unlock").json()
    assert (d["decision"], d["reason"], d["lock_state"]) == ("allow", None, "unlocked")
    assert (d["counter"], d["last_counter"]) == (1, 1)
    assert [s["status"] for s in d["trace"]] == ["pass"] * 6
    assert [s["step"] for s in d["trace"]] == [
        "key_found", "key_is_fob", "key_active_and_bound", "signature_valid", "counter_fresh", "state_committed",
    ]
    assert fob.lab.lock_state() == "unlocked"
    assert fob.press("lock").json()["lock_state"] == "locked"
    assert _last_counter(fob.lab, fob.key_id) == 2


def test_replaying_an_accepted_press_is_denied(fob):
    first = fob.press("unlock")
    assert first.json()["decision"] == "allow"
    fob.press("lock")
    replay = fob.press("unlock", counter=1, signature=fob.signature(1, "unlock")).json()
    assert (replay["decision"], replay["reason"]) == ("deny", "COUNTER_REPLAYED")
    assert replay["lock_state"] == "locked"
    assert [s["status"] for s in replay["trace"]] == ["pass", "pass", "pass", "pass", "fail", "skipped"]


def test_lower_counter_is_denied_even_if_never_used(fob):
    fob.press("unlock", counter=5, signature=fob.signature(5, "unlock"))
    d = fob.press("lock", counter=3, signature=fob.signature(3, "lock")).json()
    assert d["reason"] == "COUNTER_REPLAYED"
    assert d["last_counter"] == 5


def test_window_allows_resync_after_missed_presses_but_not_beyond(fob):
    edge = FOB_WINDOW  # last=0 → counter 32 is the furthest allowed
    assert fob.press("unlock", counter=edge, signature=fob.signature(edge, "unlock")).json()["decision"] == "allow"
    too_far = edge + FOB_WINDOW + 1
    d = fob.press("lock", counter=too_far, signature=fob.signature(too_far, "lock")).json()
    assert (d["decision"], d["reason"]) == ("deny", "COUNTER_OUT_OF_WINDOW")
    assert _last_counter(fob.lab, fob.key_id) == edge  # a rejected press never moves the counter
    assert fob.lab.lock_state() == "unlocked"


def test_invalid_signature_never_advances_the_counter(fob):
    """Unsigned junk with a large counter must not lock the owner's fob out (signature is checked first)."""
    junk = b64url_encode(b"\x01" * 64)
    d = fob.press("unlock", counter=FOB_WINDOW, signature=junk).json()
    assert d["reason"] == "SIGNATURE_INVALID"
    assert _last_counter(fob.lab, fob.key_id) == 0
    assert fob.press("unlock").json()["decision"] == "allow"  # the owner's counter 1 still works


@pytest.mark.parametrize(
    ("signed", "sent", "reason"),
    [
        ({"action": "lock"}, {"action": "unlock"}, "SIGNATURE_INVALID"),  # flipped action
        ({"counter": 2}, {"counter": 1}, "SIGNATURE_INVALID"),  # counter edited
        ({"vehicle_id": "veh_" + "Z" * 22}, {}, "SIGNATURE_INVALID"),  # signed for another car
    ],
)
def test_signature_binds_action_counter_and_vehicle(fob, signed, sent, reason):
    sig_counter = signed.get("counter", 1)
    sig = fob.signature(sig_counter, signed.get("action", "unlock"), vehicle_id=signed.get("vehicle_id"))
    d = fob.press(sent.get("action", "unlock"), counter=sent.get("counter", 1), signature=sig).json()
    assert (d["decision"], d["reason"]) == ("deny", reason)
    assert fob.lab.lock_state() == "locked"


def test_malformed_signature_is_denied(fob):
    d = fob.press("unlock", counter=1, signature="AAAA").json()
    assert d["reason"] == "SIGNATURE_MALFORMED"


# --- Status, binding, identity ---------------------------------------------------------------------


def test_revoked_fob_is_denied(fob):
    assert fob.lab.client.post(f"/api/labs/{fob.lab.id}/keys/{fob.key_id}/revoke", headers=fob.lab.headers).status_code == 200
    d = fob.press("unlock").json()
    assert (d["decision"], d["reason"]) == ("deny", "KEY_REVOKED")
    assert _last_counter(fob.lab, fob.key_id) == 0


def test_fob_for_another_vehicle_is_denied(fob):
    from test_authenticate_api import _add_vehicle

    other = _add_vehicle(fob.lab)
    d = fob.press("unlock", vehicle_id=other).json()
    assert (d["decision"], d["reason"]) == ("deny", "VEHICLE_MISMATCH")


def test_unknown_key_is_denied(fob):
    d = fob.press("unlock", key_id=new_id("key")).json()
    assert (d["decision"], d["reason"], d["last_counter"]) == ("deny", "KEY_UNKNOWN", None)


def test_another_labs_fob_is_unknown_here(client, fob):
    other = client.post("/api/labs").json()
    headers = {"Authorization": f"Bearer {other['lab_token']}"}
    other_vehicle = client.get(f"/api/labs/{other['lab_id']}/vehicles", headers=headers).json()["vehicles"][0]["id"]
    resp = client.post(
        f"/api/labs/{other['lab_id']}/fob",
        json={"vehicle_id": other_vehicle, "key_id": fob.key_id, "action": "unlock", "counter": 1,
              "signature": fob.signature(1, "unlock")},
        headers=headers,
    )
    assert resp.json()["reason"] == "KEY_UNKNOWN"
    # And this lab's fob endpoint refuses another lab's token outright.
    wrong = client.post(f"/api/labs/{fob.lab.id}/fob", json={}, headers=headers)
    assert wrong.status_code == 404 and wrong.json()["error"]["code"] == "LAB_NOT_FOUND"


# --- Cross-protocol confusion ---------------------------------------------------------------------


@pytest.mark.parametrize("credential_type", ["phone", "card"])
def test_challenge_response_keys_are_refused_at_the_fob_endpoint(lab, credential_type):
    key_id, key = _enroll(lab, credential_type)
    sig = key.sign_p1363(encode_fob_message(FobFields(lab.vehicle_id, key_id, 1, "unlock")))
    d = lab.client.post(
        f"/api/labs/{lab.id}/fob",
        json={"vehicle_id": lab.vehicle_id, "key_id": key_id, "action": "unlock", "counter": 1, "signature": sig},
        headers=lab.headers,
    ).json()
    assert (d["decision"], d["reason"]) == ("deny", "KEY_TYPE_MISMATCH")
    assert lab.lock_state() == "locked"


def test_fob_keys_cannot_get_challenges(fob):
    resp = fob.lab.challenge(fob.key_id)
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "KEY_TYPE_MISMATCH"


def test_engine_denies_a_fob_key_even_with_a_planted_challenge(fob):
    """Defense in depth: if a challenge for a fob key existed anyway, authenticate still refuses it."""
    lab = fob.lab
    engine = lab.client.app.state.engine
    chl_id = new_id("chl")
    with engine.begin() as conn:
        conn.execute(insert(challenges).values(
            id=chl_id, lab_id=lab.id, vehicle_id=lab.vehicle_id, key_id=fob.key_id,
            nonce=b64url_encode(b"\x00" * 32), action="unlock", created_at=NOW, expires_at=NOW + 30,
        ))
    chl = {"vehicle_id": lab.vehicle_id, "key_id": fob.key_id, "challenge_id": chl_id,
           "nonce": b64url_encode(b"\x00" * 32), "action": "unlock", "expires_at": NOW + 30}
    d = authenticate(engine, lab_id=lab.id, challenge_id=chl_id, key_id=fob.key_id,
                     signature=sign(fob.key, chl), clock=lab.client.app.state.clock)
    assert (d.decision, d.reason) == ("deny", "KEY_TYPE_MISMATCH")
    assert lab.lock_state() == "locked"


def test_a_fob_signature_never_verifies_as_a_challenge_response(lab):
    """Same key material, different domain tags: bytes signed for one protocol fail in the other."""
    key_id, key = _enroll(lab, "card")
    chl = lab.challenge(key_id).json()
    # Sign kg-fob-v1 bytes with the card key and present them as the challenge response.
    fob_sig = key.sign_p1363(encode_fob_message(FobFields(lab.vehicle_id, key_id, 1, "unlock")))
    d = lab.authenticate(chl["challenge_id"], key_id, fob_sig).json()
    assert (d["decision"], d["reason"]) == ("deny", "SIGNATURE_INVALID")


# --- Concurrency and events -----------------------------------------------------------------------


@pytest.mark.parametrize("round_", range(3))
def test_concurrent_identical_presses_at_most_one_allows(fob, round_):
    lab = fob.lab
    engine, clock = lab.client.app.state.engine, lab.client.app.state.clock
    sig = fob.signature(1, "unlock")
    workers = 16
    barrier = threading.Barrier(workers)
    decisions, errors, guard = [], [], threading.Lock()

    def attempt():
        try:
            barrier.wait()
            d = press_fob(engine, lab_id=lab.id, key_id=fob.key_id, vehicle_id=lab.vehicle_id, action="unlock",
                          counter=1, signature=sig, clock=clock)
            with guard:
                decisions.append((d.decision, d.reason))
        except BaseException as exc:  # pragma: no cover - surfaced by the assert below
            with guard:
                errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, errors
    assert decisions.count(("allow", None)) == 1
    assert decisions.count(("deny", "COUNTER_REPLAYED")) == workers - 1
    with engine.connect() as conn:
        assert conn.execute(select(digital_keys.c.last_counter).where(digital_keys.c.id == fob.key_id)).scalar() == 1


def test_fob_presses_are_authentication_events(fob):
    fob.press("unlock")
    fob.press("unlock", counter=1, signature=fob.signature(1, "unlock"))
    lab = fob.lab
    page = lab.client.get(f"/api/labs/{lab.id}/events", params={"category": "authentication"}, headers=lab.headers).json()
    assert [(e["event_type"], e["outcome"], e["reason"]) for e in page["events"]] == [
        ("fob_unlock", "deny", "COUNTER_REPLAYED"),
        ("fob_unlock", "allow", None),
    ]
    summary = lab.client.get(f"/api/labs/{lab.id}/events/summary", headers=lab.headers).json()
    assert summary["authentication"]["allowed"] == 1 and summary["authentication"]["denied"] == 1


@pytest.mark.parametrize(
    "body",
    [{"counter": 0}, {"counter": 2**53}, {"counter": "1"}, {"action": "start"}, {"extra": 1}, {"signature": ""}],
)
def test_fob_request_schema_is_strict(fob, body):
    payload = {"vehicle_id": fob.vehicle_id, "key_id": fob.key_id, "action": "unlock", "counter": 1,
               "signature": fob.signature(1, "unlock"), **body}
    resp = fob.lab.client.post(f"/api/labs/{fob.lab.id}/fob", json=payload, headers=fob.lab.headers)
    assert resp.status_code == 422 and resp.json()["error"]["code"] == "REQUEST_INVALID"
    assert _last_counter(fob.lab, fob.key_id) == 0


# --- Shared vectors (Python side; apps/web/tests/encoding.test.ts checks the same file) -----------


def test_fob_vectors_match_the_python_encoder():
    import json
    from pathlib import Path

    from app.security.protocol import load_public_key, verify_signature

    vec = json.loads((Path(__file__).resolve().parents[3] / "docs/test-vectors/kg-fob-v1.json").read_text())
    assert bytes.fromhex(vec["domain_tag_hex"]) == DOMAIN_TAG_FOB
    for case in vec["encoding"]:
        assert encode_fob_message(FobFields(**case["fields"])).hex() == case["message_hex"], case["name"]
    pub, _ = load_public_key(vec["verify"]["public_key_spki_b64url"])
    for case in vec["verify"]["cases"]:
        assert verify_signature(pub, bytes.fromhex(case["message_hex"]), case["signature"]) is case["expected"]
