"""Attack Lab (F05): reproducible vulnerable-vs-hardened replay comparison on disposable state."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.lab.scenarios import run_scenario
from app.lab.vulnerable.verifier import VulnerableVerifier
from app.models.tables import challenges, digital_keys, labs, vehicles
from app.security.protocol import encode_signed_message
from helpers import SimulatedClientKey


def _run(client, lab, scenario="replay", headers=None):
    return client.post(f"/api/labs/{lab['lab_id']}/scenarios/{scenario}", headers=headers or lab["headers"])


def test_replay_vulnerable_accepts_and_hardened_rejects(client, new_lab):
    resp = _run(client, new_lab)
    assert resp.status_code == 200
    body = resp.json()
    assert body["expected"] == {"vulnerable": "allow", "hardened": "deny"}
    assert body["actual"] == body["expected"]
    assert body["matches_expected"] is True

    runs = {r["mode"]: r for r in body["runs"]}
    vuln, hard = runs["vulnerable"], runs["hardened"]
    # Owner unlock and lock succeed in both modes.
    for run in (vuln, hard):
        assert [(s["actor"], s["decision"]) for s in run["steps"][:2]] == [("owner", "allow"), ("owner", "allow")]
        assert run["steps"][1]["lock_state"] == "locked"
    # The replay: vulnerable re-unlocks the car; hardened refuses and the car stays locked.
    assert (vuln["attack_decision"], vuln["final_lock_state"]) == ("allow", "unlocked")
    assert (hard["attack_decision"], hard["attack_reason"], hard["final_lock_state"]) == ("deny", "CHALLENGE_CONSUMED", "locked")


@pytest.mark.parametrize("i", range(5))
def test_replay_comparison_is_reproducible(i):
    r = run_scenario("replay", now=1_793_923_200 + i)
    assert r["actual"] == {"vulnerable": "allow", "hardened": "deny"}


def test_scenario_does_not_touch_the_labs_real_state(client, new_lab):
    lab_id = new_lab["lab_id"]
    engine = client.app.state.engine

    def snapshot():
        with engine.connect() as conn:
            return (
                conn.execute(select(vehicles.c.id, vehicles.c.lock_state).where(vehicles.c.lab_id == lab_id)).all(),
                conn.execute(select(func.count()).select_from(digital_keys).where(digital_keys.c.lab_id == lab_id)).scalar(),
                conn.execute(select(func.count()).select_from(challenges).where(challenges.c.lab_id == lab_id)).scalar(),
                conn.execute(select(func.count()).select_from(labs)).scalar(),
            )

    before = snapshot()
    for _ in range(3):
        assert _run(client, new_lab).status_code == 200
    assert snapshot() == before  # same vehicle state, no keys/challenges added, no extra labs in the real DB


def test_runs_are_recorded_per_mode(client, new_lab):
    run_id = _run(client, new_lab).json()["run_id"]
    runs = client.get(f"/api/labs/{new_lab['lab_id']}/lab-runs", headers=new_lab["headers"]).json()["runs"]
    mine = sorted((r["mode"], r["expected_result"], r["actual_result"], r["actual_reason"]) for r in runs if r["run_id"] == run_id)
    assert mine == [("hardened", "deny", "deny", "CHALLENGE_CONSUMED"), ("vulnerable", "allow", "allow", None)]


def test_catalog_lists_replay(client, new_lab):
    cat = client.get(f"/api/labs/{new_lab['lab_id']}/scenarios", headers=new_lab["headers"]).json()["scenarios"]
    assert [s["id"] for s in cat] == ["replay"]


def test_unknown_scenario_is_404(client, new_lab):
    resp = _run(client, new_lab, scenario="drop_tables")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "SCENARIO_NOT_FOUND"


def test_scenarios_are_lab_scoped(client, new_lab):
    other = client.post("/api/labs").json()
    wrong = {"Authorization": f"Bearer {other['lab_token']}"}
    assert _run(client, new_lab, headers=wrong).json()["error"]["code"] == "LAB_NOT_FOUND"
    _run(client, new_lab)
    other_runs = client.get(f"/api/labs/{other['lab_id']}/lab-runs", headers=wrong).json()["runs"]
    assert other_runs == []


def test_vulnerable_verifier_still_checks_signatures():
    """It's vulnerable to replay, not a no-op: forged signatures are still rejected."""
    v = VulnerableVerifier()
    owner, forger = SimulatedClientKey(), SimulatedClientKey()
    f = v.issue(vehicle_id="veh_" + "A" * 22, key_id="key_" + "A" * 22, spki_b64url=owner.spki_b64url, action="unlock", now=0)
    assert v.verify(challenge_id=f.challenge_id, signature=forger.sign_p1363(encode_signed_message(f))) == ("deny", "SIGNATURE_INVALID")
    assert v.lock_state == "locked"
