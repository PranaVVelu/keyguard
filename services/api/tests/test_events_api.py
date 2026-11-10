"""Events API and Security Analytics summary (F08): scoping, sanitization, filters and counts."""

from __future__ import annotations

import pytest

from conftest import NOW
from test_authenticate_api import Lab, sign


@pytest.fixture
def history(client, new_lab, clock):
    """A lab with a known mix of events, written through the public API only.

    Sequence: enroll (pass) · issue+allow (pass, pass) · replay (fail CHALLENGE_CONSUMED) ·
    issue+bad signature (pass, fail SIGNATURE_INVALID) · revoke (pass) · issue for revoked key (fail KEY_REVOKED).
    """
    lab = Lab(client, new_lab)
    key_id, key = lab.enroll()
    clock.t += 1
    chl = lab.challenge(key_id).json()
    sig = sign(key, chl)
    assert lab.authenticate(chl["challenge_id"], key_id, sig).json()["decision"] == "allow"
    clock.t += 1
    assert lab.authenticate(chl["challenge_id"], key_id, sig).json()["reason"] == "CHALLENGE_CONSUMED"
    clock.t += 1
    chl2 = lab.challenge(key_id, "lock").json()
    bad = sign(key, chl2, action="unlock")
    assert lab.authenticate(chl2["challenge_id"], key_id, bad).json()["reason"] == "SIGNATURE_INVALID"
    clock.t += 1
    assert client.post(f"/api/labs/{lab.id}/keys/{key_id}/revoke", headers=lab.headers).status_code == 200
    clock.t += 1
    assert lab.challenge(key_id).status_code == 403
    return lab, key_id, {"sig": sig, "nonce": chl["nonce"], "token": lab.token}


def _events(lab, **params):
    resp = lab.client.get(f"/api/labs/{lab.id}/events", params=params, headers=lab.headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_lists_newest_first_with_category_and_result(history):
    lab, key_id, _ = history
    page = _events(lab)
    assert page["total"] == 8
    types = [(e["event_type"], e["result"], e["reason"]) for e in page["events"]]
    assert types == [
        ("challenge_unlock", "fail", "KEY_REVOKED"),
        ("key_revoked", "pass", None),
        ("authenticate_lock", "fail", "SIGNATURE_INVALID"),
        ("challenge_lock", "pass", None),
        ("authenticate_unlock", "fail", "CHALLENGE_CONSUMED"),
        ("authenticate_unlock", "pass", None),
        ("challenge_unlock", "pass", None),
        ("key_enrolled", "pass", None),
    ]
    assert [e["created_at"] for e in page["events"]] == sorted((e["created_at"] for e in page["events"]), reverse=True)
    assert {e["category"] for e in page["events"]} == {"authentication", "challenge", "key"}
    assert all(e["id"].startswith("evt_") for e in page["events"])


def test_events_never_contain_secrets(history):
    lab, _, secrets = history
    raw = lab.client.get(f"/api/labs/{lab.id}/events", headers=lab.headers).text
    raw += lab.client.get(f"/api/labs/{lab.id}/events/summary", headers=lab.headers).text
    for value in secrets.values():
        assert value not in raw
    for field in ("signature", "nonce", "public_key", "token"):
        assert f'"{field}"' not in raw


@pytest.mark.parametrize(
    ("params", "expected_total"),
    [
        ({"result": "fail"}, 3),
        ({"result": "pass"}, 5),
        ({"category": "authentication"}, 3),
        ({"category": "authentication", "result": "fail"}, 2),
        ({"category": "key"}, 2),
        ({"category": "scenario"}, 0),
        ({"reason": "SIGNATURE_INVALID"}, 1),
        ({"q": "consumed"}, 1),  # case-insensitive over reason codes
        ({"q": "REVOK"}, 2),  # key_revoked + KEY_REVOKED
        ({"q": "%"}, 0),  # LIKE wildcards are literal, not "match everything"
        ({"q": "_"}, 8),  # every event_type contains a literal underscore
    ],
)
def test_filters_and_search(history, params, expected_total):
    lab, _, _ = history
    assert _events(lab, **params)["total"] == expected_total


def test_search_by_key_id_finds_its_events(history):
    lab, key_id, _ = history
    found = _events(lab, q=key_id)
    # Deny decisions deliberately don't attribute the caller-supplied key ID (see authenticate.py).
    assert {e["event_type"] for e in found["events"]} == {"key_enrolled", "challenge_unlock", "challenge_lock",
                                                          "authenticate_unlock", "key_revoked"}
    assert all(e["key_id"] == key_id for e in found["events"])


def test_pagination(history):
    lab, _, _ = history
    first = _events(lab, limit=3)
    second = _events(lab, limit=3, offset=3)
    rest = _events(lab, limit=3, offset=6)
    ids = [e["id"] for p in (first, second, rest) for e in p["events"]]
    assert len(ids) == 8 and len(set(ids)) == 8
    assert ids == [e["id"] for e in _events(lab, limit=200)["events"]]


def test_summary_counts_and_failure_categories(history):
    lab, _, _ = history
    s = lab.client.get(f"/api/labs/{lab.id}/events/summary", headers=lab.headers).json()
    assert (s["total"], s["pass"], s["fail"]) == (8, 5, 3)
    assert s["by_category"] == {
        "authentication": {"pass": 1, "fail": 2},
        "challenge": {"pass": 2, "fail": 1},
        "key": {"pass": 2, "fail": 0},
        "scenario": {"pass": 0, "fail": 0},
    }
    assert s["failure_reasons"] == [
        {"reason": "CHALLENGE_CONSUMED", "count": 1},
        {"reason": "KEY_REVOKED", "count": 1},
        {"reason": "SIGNATURE_INVALID", "count": 1},
    ]
    auth = s["authentication"]
    assert (auth["allowed"], auth["denied"]) == (1, 2)
    assert auth["median_ms"] is not None and auth["p95_ms"] >= auth["median_ms"]


def test_empty_lab_summary(new_lab, client):
    s = client.get(f"/api/labs/{new_lab['lab_id']}/events/summary", headers=new_lab["headers"]).json()
    assert (s["total"], s["pass"], s["fail"], s["failure_reasons"]) == (0, 0, 0, [])
    assert s["authentication"] == {"allowed": 0, "denied": 0, "median_ms": None, "p95_ms": None}


def test_events_are_scoped_to_the_lab(history, client):
    lab, key_id, _ = history
    other = client.post("/api/labs").json()
    other_headers = {"Authorization": f"Bearer {other['lab_token']}"}
    page = client.get(f"/api/labs/{other['lab_id']}/events", params={"q": key_id}, headers=other_headers).json()
    assert page["total"] == 0
    # Another lab's token can't read this lab's events, and gets the same 404 as an unknown lab.
    for path in (f"/api/labs/{lab.id}/events", f"/api/labs/{lab.id}/events/summary"):
        for headers in (other_headers, {}):
            resp = client.get(path, headers=headers)
            assert resp.status_code == 404
            assert resp.json()["error"]["code"] == "LAB_NOT_FOUND"


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 201},
        {"offset": -1},
        {"category": "bogus"},
        {"result": "maybe"},
        {"reason": "drop table"},
        {"q": "x" * 65},
        {"q": ""},
    ],
)
def test_invalid_query_parameters_are_rejected(new_lab, client, params):
    resp = client.get(f"/api/labs/{new_lab['lab_id']}/events", params=params, headers=new_lab["headers"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "REQUEST_INVALID"


def test_scenario_runs_appear_as_scenario_events(new_lab, client):
    client.post(f"/api/labs/{new_lab['lab_id']}/scenarios/replay", headers=new_lab["headers"])
    page = client.get(
        f"/api/labs/{new_lab['lab_id']}/events", params={"category": "scenario"}, headers=new_lab["headers"]
    ).json()
    assert [(e["event_type"], e["outcome"], e["result"]) for e in page["events"]] == [
        ("scenario_replay", "as_expected", "pass")
    ]
    assert page["events"][0]["created_at"] == NOW
