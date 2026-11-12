"""Values the schema must hold on every supported database (SQLite locally, PostgreSQL when hosted)."""

from __future__ import annotations

from sqlalchemy import select, update

from app.models.tables import digital_keys, labs, security_events
from app.security.fob import FOB_WINDOW
from app.security.protocol import MAX_FOB_COUNTER
from test_fob_api import Fob, _enroll
from test_authenticate_api import Lab


def test_fob_counter_holds_values_up_to_2_pow_53(client, new_lab):
    """kg-fob-v1 counters go up to 2^53 − 1 (D-010); a 32-bit INTEGER column would overflow on PostgreSQL."""
    lab = Lab(client, new_lab)
    key_id, key = _enroll(lab, "fob")
    fob = Fob(lab, key_id, key, lab.vehicle_id)
    near_max = MAX_FOB_COUNTER - FOB_WINDOW
    with client.app.state.engine.begin() as conn:
        conn.execute(update(digital_keys).where(digital_keys.c.id == key_id).values(last_counter=near_max))
    d = fob.press("unlock", counter=MAX_FOB_COUNTER, signature=fob.signature(MAX_FOB_COUNTER, "unlock")).json()
    assert (d["decision"], d["last_counter"]) == ("allow", MAX_FOB_COUNTER)
    with client.app.state.engine.connect() as conn:
        assert conn.execute(select(digital_keys.c.last_counter).where(digital_keys.c.id == key_id)).scalar() == MAX_FOB_COUNTER


def test_timestamps_after_2038_are_stored(client, clock):
    """Unix seconds pass 2^31 in January 2038; time columns must be 64-bit."""
    clock.t = 2**31 + 1000
    lab = client.post("/api/labs").json()
    assert lab["expires_at"] == clock.t + 24 * 3600
    headers = {"Authorization": f"Bearer {lab['lab_token']}"}
    assert client.get(f"/api/labs/{lab['lab_id']}/vehicles", headers=headers).status_code == 200
    with client.app.state.engine.connect() as conn:
        assert conn.execute(select(labs.c.expires_at).where(labs.c.id == lab["lab_id"])).scalar() == clock.t + 24 * 3600


def test_event_order_is_stable_across_databases(client, new_lab):
    for _ in range(3):
        client.post(f"/api/labs/{new_lab['lab_id']}/scenarios/replay", headers=new_lab["headers"])
    with client.app.state.engine.connect() as conn:
        seqs = conn.execute(select(security_events.c.seq).order_by(security_events.c.seq)).scalars().all()
    assert len(seqs) == 3 and seqs == sorted(set(seqs))


# --- Per-lab limits under concurrency (PostgreSQL READ COMMITTED doesn't serialize count-then-insert) -------

import threading  # noqa: E402

from sqlalchemy import func  # noqa: E402

from app.models.tables import challenges  # noqa: E402
from app.security.challenges import MAX_OPEN_CHALLENGES_PER_LAB  # noqa: E402
from app.security.keys import MAX_KEYS_PER_LAB  # noqa: E402
from helpers import SimulatedClientKey  # noqa: E402


def _race(n: int, fn) -> list:
    barrier, out, guard = threading.Barrier(n), [], threading.Lock()

    def run(i):
        barrier.wait()
        r = fn(i)
        with guard:
            out.append(r)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return out


def test_key_limit_holds_under_concurrent_enrollment(client, new_lab):
    keys = [SimulatedClientKey() for _ in range(MAX_KEYS_PER_LAB * 2)]
    codes = _race(len(keys), lambda i: client.post(
        f"/api/labs/{new_lab['lab_id']}/keys",
        json={"vehicle_id": new_lab["vehicle_id"], "public_key": keys[i].spki_b64url, "label": f"k{i}"},
        headers=new_lab["headers"],
    ).status_code)
    assert codes.count(201) == MAX_KEYS_PER_LAB
    with client.app.state.engine.connect() as conn:
        n = conn.execute(select(func.count()).select_from(digital_keys).where(digital_keys.c.lab_id == new_lab["lab_id"])).scalar_one()
    assert n == MAX_KEYS_PER_LAB


def test_open_challenge_limit_holds_under_concurrent_requests(client, new_lab):
    lab = Lab(client, new_lab)
    key_id, _ = lab.enroll()
    codes = _race(MAX_OPEN_CHALLENGES_PER_LAB * 2, lambda i: lab.challenge(key_id).status_code)
    assert codes.count(201) == MAX_OPEN_CHALLENGES_PER_LAB
    with client.app.state.engine.connect() as conn:
        n = conn.execute(select(func.count()).select_from(challenges).where(challenges.c.lab_id == lab.id)).scalar_one()
    assert n == MAX_OPEN_CHALLENGES_PER_LAB


def test_saved_lab_limit_holds_under_concurrent_saves(client):
    from app.security import accounts as acct
    from test_accounts_api import register
    from webauthn_sim import SoftPasskey

    account_id = register(client, SoftPasskey()).json()["account"]["id"]
    lab_ids = [client.post("/api/labs").json()["lab_id"] for _ in range(acct.SAVED_LAB_LIMIT + 5)]
    engine, now = client.app.state.engine, client.app.state.clock()

    def save(i):
        try:
            acct.save_lab(engine, account_id=account_id, lab_id=lab_ids[i], now=now)
            return "saved"
        except acct.AccountError as exc:
            return exc.code

    results = _race(len(lab_ids), save)
    assert results.count("saved") == acct.SAVED_LAB_LIMIT
    assert results.count("SAVED_LAB_LIMIT_REACHED") == 5
