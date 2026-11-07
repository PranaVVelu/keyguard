"""Key enrollment over HTTP (F02): the client sends a public key only; the server validates and binds it."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select

from app.models.tables import digital_keys, security_events
from app.security.encoding import b64url_decode, b64url_encode
from app.security.keys import MAX_KEYS_PER_LAB
from conftest import NOW
from helpers import SimulatedClientKey


def _enroll(client, lab, *, public_key=None, label="phone", vehicle_id=None, headers=None):
    return client.post(
        f"/api/labs/{lab['lab_id']}/keys",
        json={
            "vehicle_id": vehicle_id or lab["vehicle_id"],
            "public_key": public_key or SimulatedClientKey().spki_b64url,
            "label": label,
        },
        headers=headers or lab["headers"],
    )


def _spki(private_key) -> str:
    return b64url_encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def test_enroll_returns_metadata_and_lists_key(client, new_lab):
    key = SimulatedClientKey()
    resp = _enroll(client, new_lab, public_key=key.spki_b64url, label="Pranav's phone")
    assert resp.status_code == 201
    body = resp.json()
    assert body["id"].startswith("key_")
    assert body["vehicle_id"] == new_lab["vehicle_id"]
    assert body["status"] == "active"
    assert body["created_at"] == NOW
    assert body["revoked_at"] is None
    assert body["fingerprint"] == hashlib.sha256(b64url_decode(key.spki_b64url)).hexdigest()
    assert "public_key" not in body

    listed = client.get(f"/api/labs/{new_lab['lab_id']}/keys", headers=new_lab["headers"]).json()["keys"]
    assert listed == [body]


def test_server_stores_only_the_public_key(client, new_lab):
    key = SimulatedClientKey()
    key_id = _enroll(client, new_lab, public_key=key.spki_b64url).json()["id"]
    with client.app.state.engine.connect() as conn:
        stored = conn.execute(select(digital_keys.c.public_key).where(digital_keys.c.id == key_id)).scalar_one()
    assert stored == b64url_decode(key.spki_b64url)
    assert len(stored) == 91  # P-256 SPKI; no private scalar anywhere


def test_extra_fields_such_as_private_key_are_rejected(client, new_lab):
    resp = client.post(
        f"/api/labs/{new_lab['lab_id']}/keys",
        json={
            "vehicle_id": new_lab["vehicle_id"],
            "public_key": SimulatedClientKey().spki_b64url,
            "label": "phone",
            "private_key": "AAAA",
        },
        headers=new_lab["headers"],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "REQUEST_INVALID"


@pytest.mark.parametrize(
    "make, code",
    [
        (lambda: _spki(ec.generate_private_key(ec.SECP384R1())), "PUBLIC_KEY_UNSUPPORTED"),
        (lambda: _spki(rsa.generate_private_key(public_exponent=65537, key_size=2048)), "REQUEST_INVALID"),
        (lambda: b64url_encode(b"garbage"), "PUBLIC_KEY_INVALID"),
        (lambda: "not base64url!", "PUBLIC_KEY_INVALID"),
    ],
    ids=["p384", "rsa-too-long", "garbage", "bad-charset"],
)
def test_invalid_public_keys_are_rejected(client, new_lab, make, code):
    resp = _enroll(client, new_lab, public_key=make())
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == code
    assert client.get(f"/api/labs/{new_lab['lab_id']}/keys", headers=new_lab["headers"]).json()["keys"] == []


@pytest.mark.parametrize("label", ["", " padded ", "x" * 41, "bell\x07", "new\nline"])
def test_invalid_labels_are_rejected(client, new_lab, label):
    resp = _enroll(client, new_lab, label=label)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "REQUEST_INVALID"


def test_cannot_enroll_against_another_labs_vehicle(client, new_lab):
    other = client.post("/api/labs").json()
    other_headers = {"Authorization": f"Bearer {other['lab_token']}"}
    other_vehicle = client.get(f"/api/labs/{other['lab_id']}/vehicles", headers=other_headers).json()["vehicles"][0]["id"]

    resp = _enroll(client, new_lab, vehicle_id=other_vehicle)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "VEHICLE_NOT_FOUND"
    # And the other lab didn't gain a key either.
    assert client.get(f"/api/labs/{other['lab_id']}/keys", headers=other_headers).json()["keys"] == []


def test_cross_lab_key_listing_and_enrollment_are_denied(client, new_lab):
    other = client.post("/api/labs").json()
    wrong = {"Authorization": f"Bearer {other['lab_token']}"}
    assert client.get(f"/api/labs/{new_lab['lab_id']}/keys", headers=wrong).status_code == 404
    resp = _enroll(client, new_lab, headers=wrong)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "LAB_NOT_FOUND"


def test_same_public_key_cannot_be_enrolled_twice(client, new_lab):
    spki = SimulatedClientKey().spki_b64url
    assert _enroll(client, new_lab, public_key=spki).status_code == 201
    resp = _enroll(client, new_lab, public_key=spki, label="again")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "KEY_ALREADY_ENROLLED"


def test_key_limit_per_lab(client, new_lab):
    for i in range(MAX_KEYS_PER_LAB):
        assert _enroll(client, new_lab, label=f"k{i}").status_code == 201
    resp = _enroll(client, new_lab, label="one-too-many")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "KEY_LIMIT_REACHED"


def test_enrollment_events_record_ids_and_reasons_only(client, new_lab):
    spki = SimulatedClientKey().spki_b64url
    _enroll(client, new_lab, public_key=spki)
    _enroll(client, new_lab, public_key=spki)  # duplicate → denied
    with client.app.state.engine.connect() as conn:
        rows = conn.execute(
            select(security_events.c.event_type, security_events.c.outcome, security_events.c.reason)
            .where(security_events.c.lab_id == new_lab["lab_id"])
            .order_by(security_events.c.id)
        ).all()
        all_text = " ".join(str(v) for row in conn.execute(select(security_events)).all() for v in row)
    assert sorted(rows) == sorted(
        [("key_enrolled", "success", None), ("key_enrolled", "denied", "KEY_ALREADY_ENROLLED")]
    )
    assert spki not in all_text
    assert new_lab["lab_token"] not in all_text


# --- Revocation (F06) ---------------------------------------------------------------------


def _revoke(client, lab, key_id, headers=None):
    return client.post(f"/api/labs/{lab['lab_id']}/keys/{key_id}/revoke", headers=headers or lab["headers"])


def test_revoke_marks_key_revoked_with_timestamp(client, new_lab, clock):
    key_id = _enroll(client, new_lab).json()["id"]
    clock.t = NOW + 60
    resp = _revoke(client, new_lab, key_id)
    assert resp.status_code == 200
    body = resp.json()
    assert (body["id"], body["status"], body["revoked_at"]) == (key_id, "revoked", NOW + 60)
    listed = client.get(f"/api/labs/{new_lab['lab_id']}/keys", headers=new_lab["headers"]).json()["keys"]
    assert listed == [body]


def test_revoke_is_idempotent_and_keeps_first_timestamp(client, new_lab, clock):
    key_id = _enroll(client, new_lab).json()["id"]
    first = _revoke(client, new_lab, key_id).json()
    clock.t = NOW + 999
    second = _revoke(client, new_lab, key_id)
    assert second.status_code == 200
    assert second.json()["revoked_at"] == first["revoked_at"]


def test_revoke_only_affects_the_named_key(client, new_lab):
    a = _enroll(client, new_lab, label="a").json()["id"]
    b = _enroll(client, new_lab, label="b").json()["id"]
    _revoke(client, new_lab, a)
    status = {k["id"]: k["status"] for k in client.get(f"/api/labs/{new_lab['lab_id']}/keys", headers=new_lab["headers"]).json()["keys"]}
    assert status == {a: "revoked", b: "active"}


@pytest.mark.parametrize("key_id", ["key_" + "Q" * 22, "nonsense", "key_../../x"])
def test_revoke_unknown_key_is_404(client, new_lab, key_id):
    resp = _revoke(client, new_lab, key_id)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] in ("KEY_UNKNOWN", "NOT_FOUND")


def test_cannot_revoke_another_labs_key(client, new_lab):
    victim_key = _enroll(client, new_lab).json()["id"]
    other = client.post("/api/labs").json()
    other_headers = {"Authorization": f"Bearer {other['lab_token']}"}
    # Using lab B's token on lab A's URL → lab not found.
    assert _revoke(client, new_lab, victim_key, headers=other_headers).json()["error"]["code"] == "LAB_NOT_FOUND"
    # Using lab B's own URL with lab A's key ID → key not found in lab B.
    resp = client.post(f"/api/labs/{other['lab_id']}/keys/{victim_key}/revoke", headers=other_headers)
    assert resp.json()["error"]["code"] == "KEY_UNKNOWN"
    status = client.get(f"/api/labs/{new_lab['lab_id']}/keys", headers=new_lab["headers"]).json()["keys"][0]["status"]
    assert status == "active"


def test_revocation_is_logged(client, new_lab):
    key_id = _enroll(client, new_lab).json()["id"]
    _revoke(client, new_lab, key_id)
    with client.app.state.engine.connect() as conn:
        rows = conn.execute(
            select(security_events.c.event_type, security_events.c.key_id).where(security_events.c.event_type == "key_revoked")
        ).all()
    assert rows == [("key_revoked", key_id)]
