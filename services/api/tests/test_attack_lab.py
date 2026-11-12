"""Attack Lab (F05, F09): reproducible vulnerable-vs-hardened replay, tamper and substitute comparisons on disposable state."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.lab.scenarios import SCENARIOS, _flip_last_byte, run_scenario
from app.lab.vulnerable.client_bytes import ClientBytesVerifier, parse_signed_message
from app.lab.vulnerable.verifier import VulnerableVerifier
from app.security.encoding import b64url_encode
from app.models.tables import challenges, digital_keys, labs, vehicles
from app.security.protocol import SignedFields, encode_signed_message, load_public_key, verify_signature
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


def test_catalog_lists_every_scenario(client, new_lab):
    cat = client.get(f"/api/labs/{new_lab['lab_id']}/scenarios", headers=new_lab["headers"]).json()["scenarios"]
    assert [(s["id"], s["expected"]) for s in cat] == [
        ("replay", {"vulnerable": "allow", "hardened": "deny"}),
        ("tamper", {"vulnerable": "deny", "hardened": "deny"}),
        ("substitute", {"vulnerable": "allow", "hardened": "deny"}),
        ("fob-replay", {"vulnerable": "allow", "hardened": "deny"}),
        ("fob-capture", {"vulnerable": "allow", "hardened": "allow"}),
        ("relay", {"vulnerable": "allow", "hardened": "allow"}),
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


# --- substitute: verifying client-supplied signed bytes -----------------------------------------


def test_substitute_vulnerable_unlocks_and_hardened_denies_signature_invalid(client, new_lab):
    body = _run(client, new_lab, scenario="substitute").json()
    assert body["expected"] == body["actual"] == {"vulnerable": "allow", "hardened": "deny"}
    assert body["matches_expected"] is True
    assert body["attack_label"] == "Substituted message"

    runs = {r["mode"]: r for r in body["runs"]}
    common = [
        ("owner", "allow", None, "unlocked"),  # the captured unlock is genuine
        ("owner", "allow", None, "locked"),
        ("attacker", "deny", "CHALLENGE_CONSUMED", "locked"),  # both verifiers enforce single use
    ]
    steps = {m: [(s["actor"], s["decision"], s["reason"], s["lock_state"]) for s in r["steps"]] for m, r in runs.items()}
    assert steps["vulnerable"] == [*common, ("attacker", "allow", None, "unlocked")]
    assert steps["hardened"] == [*common, ("attacker", "deny", "SIGNATURE_INVALID", "locked")]
    assert (runs["vulnerable"]["attack_decision"], runs["vulnerable"]["final_lock_state"]) == ("allow", "unlocked")
    hard = runs["hardened"]
    assert (hard["attack_decision"], hard["attack_reason"], hard["final_lock_state"]) == ("deny", "SIGNATURE_INVALID", "locked")


@pytest.mark.parametrize("i", range(5))
def test_substitute_comparison_is_reproducible(i):
    r = run_scenario("substitute", now=1_793_923_200 + i)
    assert r["actual"] == {"vulnerable": "allow", "hardened": "deny"}


def test_substitute_runs_are_recorded_per_mode(client, new_lab):
    run_id = _run(client, new_lab, scenario="substitute").json()["run_id"]
    runs = client.get(f"/api/labs/{new_lab['lab_id']}/lab-runs", headers=new_lab["headers"]).json()["runs"]
    mine = sorted((r["scenario"], r["mode"], r["expected_result"], r["actual_result"], r["actual_reason"]) for r in runs if r["run_id"] == run_id)
    assert mine == [
        ("substitute", "hardened", "deny", "deny", "SIGNATURE_INVALID"),
        ("substitute", "vulnerable", "allow", "allow", None),
    ]


def _client_bytes_setup():
    v, owner = ClientBytesVerifier(), SimulatedClientKey()
    ids = {"vehicle_id": "veh_" + "A" * 22, "key_id": "key_" + "A" * 22, "spki_b64url": owner.spki_b64url, "now": 0}

    def respond(f):
        msg = encode_signed_message(f)
        return {"signed_message": b64url_encode(msg), "signature": owner.sign_p1363(msg)}

    return v, owner, ids, respond


def test_client_bytes_verifier_enforces_single_use_and_checks_signatures():
    """It's not a no-op: a second submission on the same challenge and a forged signature are both refused."""
    v, _, ids, respond = _client_bytes_setup()
    unlock = v.issue(action="unlock", **ids)
    genuine = respond(unlock)
    assert v.verify(challenge_id=unlock.challenge_id, **genuine) == ("allow", None)
    assert v.verify(challenge_id=unlock.challenge_id, **genuine) == ("deny", "CHALLENGE_CONSUMED")

    forger = SimulatedClientKey()
    lock = v.issue(action="lock", **ids)
    msg = encode_signed_message(lock)
    forged = {"signed_message": b64url_encode(msg), "signature": forger.sign_p1363(msg)}
    assert v.verify(challenge_id=lock.challenge_id, **forged) == ("deny", "SIGNATURE_INVALID")
    assert v.lock_state == "unlocked"  # the forged lock did nothing


def test_substituted_bytes_name_another_challenge_but_still_verify_in_the_vulnerable_verifier():
    """The root cause: the signature is genuine over the OLD unlock bytes, which name the old challenge and action.
    The vulnerable verifier checks those bytes; the hardened rebuild from the fresh lock challenge doesn't match."""
    v, owner, ids, respond = _client_bytes_setup()
    unlock = v.issue(action="unlock", **ids)
    captured = respond(unlock)
    assert v.verify(challenge_id=unlock.challenge_id, **captured) == ("allow", None)
    lock = v.issue(action="lock", **ids)
    assert v.verify(challenge_id=lock.challenge_id, **respond(lock)) == ("allow", None)

    fresh_lock = v.issue(action="lock", **ids)
    fields = parse_signed_message(encode_signed_message(unlock))
    assert (fields[3], fields[5]) == (unlock.challenge_id, "unlock")  # not fresh_lock's ID, not "lock"

    public_key, _ = load_public_key(owner.spki_b64url)
    rebuilt = encode_signed_message(fresh_lock)  # what the hardened engine checks
    assert verify_signature(public_key, rebuilt, captured["signature"]) is False

    assert v.verify(challenge_id=fresh_lock.challenge_id, **captured) == ("allow", None)
    assert v.lock_state == "unlocked"  # a lock challenge just unlocked the car


@pytest.mark.parametrize(
    "mangle",
    [
        lambda m: m[1:],  # no domain tag
        lambda m: m[:-1],  # truncated
        lambda m: m + b"\x00",  # trailing bytes
    ],
    ids=["no-tag", "truncated", "trailing"],
)
def test_parse_signed_message_rejects_malformed_framing(mangle):
    v, _, ids, _ = _client_bytes_setup()
    msg = encode_signed_message(v.issue(action="unlock", **ids))
    assert len(parse_signed_message(msg)) == 7
    with pytest.raises(Exception, match="MESSAGE_MALFORMED"):
        parse_signed_message(mangle(msg))


def test_substitution_through_the_real_api_is_denied_and_signed_bytes_are_not_accepted(client, new_lab):
    """The same attack against the production HTTP API, outside the lab: the old unlock signature on a fresh lock
    challenge is SIGNATURE_INVALID, and there is no way to send signed bytes (an extra field is a 422)."""
    lab_id, headers, vehicle_id = new_lab["lab_id"], new_lab["headers"], new_lab["vehicle_id"]
    owner = SimulatedClientKey()
    key_id = client.post(
        f"/api/labs/{lab_id}/keys", json={"vehicle_id": vehicle_id, "public_key": owner.spki_b64url, "label": "k"}, headers=headers
    ).json()["id"]

    def challenge(action):
        chl = client.post(f"/api/labs/{lab_id}/challenges", json={"vehicle_id": vehicle_id, "key_id": key_id, "action": action}, headers=headers).json()
        fields = {k: chl[k] for k in ("vehicle_id", "key_id", "challenge_id", "nonce", "action", "expires_at")}
        return chl["challenge_id"], encode_signed_message(SignedFields(**fields))

    def authenticate(**body):
        return client.post(f"/api/labs/{lab_id}/authenticate", json={"key_id": key_id, **body}, headers=headers)

    def lock_state():
        vs = client.get(f"/api/labs/{lab_id}/vehicles", headers=headers).json()["vehicles"]
        return next(v for v in vs if v["id"] == vehicle_id)["lock_state"]

    unlock_id, unlock_msg = challenge("unlock")
    captured_sig = owner.sign_p1363(unlock_msg)
    assert authenticate(challenge_id=unlock_id, signature=captured_sig).json()["decision"] == "allow"
    lock_id, lock_msg = challenge("lock")
    assert authenticate(challenge_id=lock_id, signature=owner.sign_p1363(lock_msg)).json()["decision"] == "allow"

    fresh_id, _ = challenge("lock")
    with_bytes = authenticate(challenge_id=fresh_id, signature=captured_sig, signed_message=b64url_encode(unlock_msg))
    assert with_bytes.status_code == 422
    assert with_bytes.json()["error"]["code"] == "REQUEST_INVALID"

    body = authenticate(challenge_id=fresh_id, signature=captured_sig).json()
    assert (body["decision"], body["reason"]) == ("deny", "SIGNATURE_INVALID")
    assert lock_state() == "locked"



# --- Sprint 9: key fob (D-010) and relay (D-011) scenarios ------------------------------------------


@pytest.mark.parametrize(
    ("scenario", "vulnerable", "hardened"),
    [
        ("fob-replay", ("allow", None), ("deny", "COUNTER_REPLAYED")),
        ("fob-capture", ("allow", None), ("allow", None)),
        ("relay", ("allow", None), ("allow", None)),
    ],
)
def test_new_scenarios_through_the_api(client, new_lab, scenario, vulnerable, hardened):
    body = _run(client, new_lab, scenario=scenario).json()
    assert body["matches_expected"] is True
    runs = {r["mode"]: r for r in body["runs"]}
    assert (runs["vulnerable"]["attack_decision"], runs["vulnerable"]["attack_reason"]) == vulnerable
    assert (runs["hardened"]["attack_decision"], runs["hardened"]["attack_reason"]) == hardened
    # Owner steps are genuine and allowed in every mode: the attack is the only variable.
    for r in body["runs"]:
        assert all(s["decision"] == "allow" for s in r["steps"] if s["actor"] == "owner")


@pytest.mark.parametrize("scenario", ["fob-replay", "fob-capture", "relay"])
@pytest.mark.parametrize("i", range(3))
def test_new_scenarios_are_reproducible(scenario, i):
    r = run_scenario(scenario, now=1_793_923_200 + i)
    assert r["matches_expected"], r["actual"]


def test_counterless_receiver_still_checks_signatures():
    from app.lab.vulnerable.fob import CounterlessFobReceiver
    from app.security.protocol import FobFields, encode_fob_message

    owner, attacker = SimulatedClientKey(), SimulatedClientKey()
    rx = CounterlessFobReceiver(vehicle_id="veh_" + "V" * 22, key_id="key_" + "V" * 22, spki_b64url=owner.spki_b64url)
    forged = attacker.sign_p1363(encode_fob_message(FobFields("veh_" + "V" * 22, "key_" + "V" * 22, 1, "unlock")))
    assert rx.press(counter=1, action="unlock", signature=forged) == ("deny", "SIGNATURE_INVALID")
    assert rx.lock_state == "locked"


def test_relay_hardened_run_uses_a_card_credential():
    """The relay story depends on the passive card; make sure the sandbox really enrolls one."""
    from app.lab import scenarios

    seen = {}
    real_enroll = scenarios.enroll_key

    def spy(*a, **kw):
        seen["credential_type"] = kw.get("credential_type")
        return real_enroll(*a, **kw)

    scenarios.enroll_key = spy
    try:
        run_scenario("relay", now=1_793_923_200)
    finally:
        scenarios.enroll_key = real_enroll
    assert seen["credential_type"] == "card"
