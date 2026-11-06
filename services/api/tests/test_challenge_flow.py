"""Standalone protocol round-trip (spec §13 acceptance item) and challenge single-use rules.

Covers: generate key pair → enroll public key → issue challenge → client signs →
server rebuilds bytes and verifies → consume → replay rejected.
"""

from __future__ import annotations

import threading

import pytest

from app.db import make_engine
from app.security.challenges import (
    CHALLENGE_TTL_SECONDS,
    ConsumeResult,
    consume_challenge,
    get_challenge,
    issue_challenge,
)
from app.security.keys import enroll_key, get_key_spki
from app.security.labs import create_lab
from app.security.protocol import encode_signed_message, load_public_key, verify_signature
from helpers import SimulatedClientKey

NOW = 1_793_923_200


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'kg.db'}")
    yield eng
    eng.dispose()


@pytest.fixture
def lab(engine):
    client_key = SimulatedClientKey()
    with engine.begin() as conn:
        new = create_lab(conn, now=NOW)
        key_id = enroll_key(
            conn, lab_id=new.lab_id, vehicle_id=new.vehicle_id, spki_b64url=client_key.spki_b64url, label="phone", now=NOW
        )
    return new, key_id, client_key


def _issue(engine, new, key_id, action="unlock", now=NOW):
    with engine.begin() as conn:
        return issue_challenge(conn, lab_id=new.lab_id, vehicle_id=new.vehicle_id, key_id=key_id, action=action, now=now)


def _server_verify(engine, lab_id, challenge_id, key_id, signature) -> bool:
    """Server side: rebuild the canonical bytes from the stored row, never from client input."""
    with engine.connect() as conn:
        chl = get_challenge(conn, lab_id=lab_id, challenge_id=challenge_id)
        spki = get_key_spki(conn, lab_id=lab_id, key_id=key_id)
    public_key, _ = load_public_key(spki)
    return verify_signature(public_key, encode_signed_message(chl.signed_fields()), signature)


def test_round_trip_then_replay_rejected(engine, lab):
    new, key_id, client_key = lab
    chl = _issue(engine, new, key_id)

    signature = client_key.sign_p1363(encode_signed_message(chl.signed_fields()))
    assert _server_verify(engine, new.lab_id, chl.id, key_id, signature)

    with engine.begin() as conn:
        assert consume_challenge(conn, lab_id=new.lab_id, challenge_id=chl.id, now=NOW + 1) is ConsumeResult.CONSUMED

    # Replay: the signature is still valid, but the challenge is spent.
    assert _server_verify(engine, new.lab_id, chl.id, key_id, signature)
    with engine.begin() as conn:
        assert (
            consume_challenge(conn, lab_id=new.lab_id, challenge_id=chl.id, now=NOW + 2)
            is ConsumeResult.ALREADY_CONSUMED
        )


def test_issued_challenges_are_unique_and_short_lived(engine, lab):
    new, key_id, _ = lab
    a, b = _issue(engine, new, key_id), _issue(engine, new, key_id)
    assert a.id != b.id and a.nonce != b.nonce
    assert a.expires_at == NOW + CHALLENGE_TTL_SECONDS
    assert a.consumed_at is None


def test_signature_from_other_key_is_rejected(engine, lab):
    new, key_id, _ = lab
    chl = _issue(engine, new, key_id)
    forged = SimulatedClientKey().sign_p1363(encode_signed_message(chl.signed_fields()))
    assert not _server_verify(engine, new.lab_id, chl.id, key_id, forged)


def test_signature_for_lock_does_not_authorize_unlock(engine, lab):
    new, key_id, client_key = lab
    lock_chl = _issue(engine, new, key_id, action="lock")
    unlock_chl = _issue(engine, new, key_id, action="unlock")
    lock_sig = client_key.sign_p1363(encode_signed_message(lock_chl.signed_fields()))
    assert not _server_verify(engine, new.lab_id, unlock_chl.id, key_id, lock_sig)


def test_signature_for_other_vehicle_is_rejected(engine, lab):
    new, key_id, client_key = lab
    chl = _issue(engine, new, key_id)
    other_vehicle = chl.signed_fields().__class__(**{**chl.signed_fields().__dict__, "vehicle_id": "veh_" + "Z" * 22})
    sig = client_key.sign_p1363(encode_signed_message(other_vehicle))
    assert not _server_verify(engine, new.lab_id, chl.id, key_id, sig)


def test_expired_challenge_cannot_be_consumed(engine, lab):
    new, key_id, _ = lab
    chl = _issue(engine, new, key_id)
    with engine.begin() as conn:
        # expires_at is exclusive: at exactly expires_at the challenge is already dead.
        assert (
            consume_challenge(conn, lab_id=new.lab_id, challenge_id=chl.id, now=chl.expires_at)
            is ConsumeResult.EXPIRED
        )


def test_consumption_is_lab_scoped(engine, lab):
    new, key_id, _ = lab
    chl = _issue(engine, new, key_id)
    with engine.begin() as conn:
        other = create_lab(conn, now=NOW)
        assert consume_challenge(conn, lab_id=other.lab_id, challenge_id=chl.id, now=NOW) is ConsumeResult.NOT_FOUND
    with engine.begin() as conn:
        assert consume_challenge(conn, lab_id=new.lab_id, challenge_id=chl.id, now=NOW) is ConsumeResult.CONSUMED


def test_rolled_back_consumption_leaves_challenge_usable(engine, lab):
    new, key_id, _ = lab
    chl = _issue(engine, new, key_id)
    with pytest.raises(RuntimeError):
        with engine.begin() as conn:
            assert consume_challenge(conn, lab_id=new.lab_id, challenge_id=chl.id, now=NOW) is ConsumeResult.CONSUMED
            raise RuntimeError("state transition failed")
    with engine.begin() as conn:
        assert consume_challenge(conn, lab_id=new.lab_id, challenge_id=chl.id, now=NOW) is ConsumeResult.CONSUMED


@pytest.mark.parametrize("round_", range(10))
def test_concurrent_consumers_at_most_one_succeeds(engine, lab, round_):
    new, key_id, _ = lab
    chl = _issue(engine, new, key_id)
    workers = 16
    barrier = threading.Barrier(workers)
    results: list[ConsumeResult] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def attempt():
        try:
            barrier.wait()
            with engine.begin() as conn:
                r = consume_challenge(conn, lab_id=new.lab_id, challenge_id=chl.id, now=NOW + 1)
            with lock:
                results.append(r)
        except BaseException as exc:  # an infrastructure failure must fail the test, not hide
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len(results) == workers
    assert results.count(ConsumeResult.CONSUMED) == 1
    assert results.count(ConsumeResult.ALREADY_CONSUMED) == workers - 1
