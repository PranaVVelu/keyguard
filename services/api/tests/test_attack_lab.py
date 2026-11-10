"""Attack Lab (F05, F09): reproducible vulnerable-vs-hardened replay and tamper comparisons on disposable state."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.lab.scenarios import SCENARIOS, _flip_last_byte, run_scenario
from app.lab.vulnerable.verifier import VulnerableVerifier
from app.models.tables import challenges, digital_keys, labs, vehicles
from app.security.protocol import encode_signed_message, load_public_key, verify_signature
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


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_scenario_does_not_touch_the_labs_real_state(client, new_lab, scenario):
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
        assert _run(client, new_lab, scenario=scenario).status_code == 200
    assert snapshot() == before  # same vehicle state, no keys/challenges added, no extra labs in the real DB


def test_runs_are_recorded_per_mode(client, new_lab):
    run_id = _run(client, new_lab).json()["run_id"]
    runs = client.get(f"/api/labs/{new_lab['lab_id']}/lab-runs", headers=new_lab["headers"]).json()["runs"]
    mine = sorted((r["mode"], r["expected_result"], r["actual_result"], r["actual_reason"]) for r in runs if r["run_id"] == run_id)
    assert mine == [("hardened", "deny", "deny", "CHALLENGE_CONSUMED"), ("vulnerable", "allow", "allow", None)]


def test_catalog_lists_replay_and_tamper(client, new_lab):
    cat = client.get(f"/api/labs/{new_lab['lab_id']}/scenarios", headers=new_lab["headers"]).json()["scenarios"]
    assert [(s["id"], s["expected"]) for s in cat] == [
        ("replay", {"vulnerable": "allow", "hardened": "deny"}),
        ("tamper", {"vulnerable": "deny", "hardened": "deny"}),
    ]
    for s in cat:  # the UI renders these instead of hard-coded replay copy
        assert s["attack_label"] and s["takeaway"]
        assert set(s["mode_notes"]) == {"vulnerable", "hardened"}


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


# --- F09: tampering ---------------------------------------------------------------------------


def test_tamper_is_rejected_by_both_verifiers_with_signature_invalid(client, new_lab):
    body = _run(client, new_lab, scenario="tamper").json()
    assert body["expected"] == body["actual"] == {"vulnerable": "deny", "hardened": "deny"}
    assert body["matches_expected"] is True
    assert body["attack_label"] == "Tampered response"

    for run in body["runs"]:
        steps = [(s["actor"], s["decision"], s["reason"], s["lock_state"]) for s in run["steps"]]
        assert steps == [
            ("owner", "allow", None, "locked"),  # the owner's genuine lock works
            ("attacker", "deny", "SIGNATURE_INVALID", "locked"),  # lock signature stapled onto an unlock challenge
            ("attacker", "deny", "SIGNATURE_INVALID", "locked"),  # one signature byte flipped in flight
        ], run["mode"]
        assert (run["attack_decision"], run["attack_reason"], run["final_lock_state"]) == ("deny", "SIGNATURE_INVALID", "locked")


@pytest.mark.parametrize("i", range(5))
def test_tamper_comparison_is_reproducible(i):
    r = run_scenario("tamper", now=1_793_923_200 + i)
    assert r["actual"] == {"vulnerable": "deny", "hardened": "deny"}
    assert {run["attack_reason"] for run in r["runs"]} == {"SIGNATURE_INVALID"}


def test_tamper_runs_are_recorded_per_mode(client, new_lab):
    run_id = _run(client, new_lab, scenario="tamper").json()["run_id"]
    runs = client.get(f"/api/labs/{new_lab['lab_id']}/lab-runs", headers=new_lab["headers"]).json()["runs"]
    mine = sorted((r["scenario"], r["mode"], r["expected_result"], r["actual_result"], r["actual_reason"]) for r in runs if r["run_id"] == run_id)
    assert mine == [
        ("tamper", "hardened", "deny", "deny", "SIGNATURE_INVALID"),
        ("tamper", "vulnerable", "deny", "deny", "SIGNATURE_INVALID"),
    ]


def test_stapled_signature_is_genuine_but_bound_to_the_servers_bytes():
    """Why the stapling attack fails: the lock signature is valid over the lock challenge's bytes, but the
    verifier rebuilds the bytes from the unlock challenge it stored (different action, ID and nonce)."""
    v = VulnerableVerifier()
    owner = SimulatedClientKey()
    ids = {"vehicle_id": "veh_" + "A" * 22, "key_id": "key_" + "A" * 22, "spki_b64url": owner.spki_b64url, "now": 0}
    lock, unlock = v.issue(action="lock", **ids), v.issue(action="unlock", **ids)
    lock_sig = owner.sign_p1363(encode_signed_message(lock))
    public_key, _ = load_public_key(owner.spki_b64url)

    assert verify_signature(public_key, encode_signed_message(lock), lock_sig) is True
    assert verify_signature(public_key, encode_signed_message(unlock), lock_sig) is False
    # Even the replayable verifier rejects it, because it never takes the signed bytes from the request.
    assert v.verify(challenge_id=unlock.challenge_id, signature=lock_sig) == ("deny", "SIGNATURE_INVALID")
    assert v.lock_state == "locked"


def test_flipped_signature_byte_is_invalid_not_malformed():
    owner = SimulatedClientKey()
    v = VulnerableVerifier()
    f = v.issue(vehicle_id="veh_" + "A" * 22, key_id="key_" + "A" * 22, spki_b64url=owner.spki_b64url, action="unlock", now=0)
    sig = owner.sign_p1363(encode_signed_message(f))
    tampered = _flip_last_byte(sig)
    assert tampered != sig and len(tampered) == len(sig)
    assert v.verify(challenge_id=f.challenge_id, signature=tampered) == ("deny", "SIGNATURE_INVALID")
    assert v.verify(challenge_id=f.challenge_id, signature=sig) == ("allow", None)  # the untouched one still verifies
