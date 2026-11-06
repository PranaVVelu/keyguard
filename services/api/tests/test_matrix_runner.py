"""The evidence runner must report honestly: all pass on the real engine, and the right failure class otherwise."""

from __future__ import annotations

import json

import pytest

import app.security.authenticate as engine_module
from app.evidence import matrix
from app.evidence.matrix import Observation, Scenario, classify, run_matrix, run_scenario
from app.security.challenges import ConsumeResult


def test_all_mandatory_scenarios_pass_on_real_engine():
    report = run_matrix()
    assert report["summary"] == {"total": 11, "pass": 11}, json.dumps(report["results"], indent=2)
    assert [r["id"] for r in report["results"]] == [f"MX-{i:02d}" for i in range(1, 12)]
    for r in report["results"]:
        assert r["duration_ms"] >= 0
        assert r["observed"] is not None


def test_cli_writes_json_and_markdown_and_exits_zero(tmp_path):
    rc = matrix.main(["--json", str(tmp_path / "m.json"), "--markdown", str(tmp_path / "m.md")])
    assert rc == 0
    data = json.loads((tmp_path / "m.json").read_text())
    assert data["summary"]["pass"] == 11
    assert "| MX-05 |" in (tmp_path / "m.md").read_text()


def test_broken_replay_protection_is_reported_as_security_failure(monkeypatch):
    """If consumption silently always succeeds, the runner must flag replay and concurrency as security failures."""
    monkeypatch.setattr(engine_module, "consume_challenge", lambda *a, **k: ConsumeResult.CONSUMED)
    report = run_matrix()
    by_id = {r["id"]: r for r in report["results"]}
    assert by_id["MX-05"]["outcome"] == "security_failure"
    assert by_id["MX-08"]["outcome"] == "security_failure"
    assert by_id["MX-04"]["outcome"] == "security_failure"  # expiry is enforced inside the consume
    assert by_id["MX-01"]["outcome"] == "pass"
    assert matrix.main([]) == 1


S = Scenario("T", "t", "deny", ("SIGNATURE_INVALID",))


@pytest.mark.parametrize(
    "scenario, obs, outcome",
    [
        (S, Observation("deny", "SIGNATURE_INVALID"), "pass"),
        (S, Observation("allow", None, True), "security_failure"),
        (S, Observation("deny", "SIGNATURE_INVALID", state_changed=True), "security_failure"),
        (S, Observation("deny", "KEY_REVOKED"), "functional_failure"),
        (S, Observation("reject", "REQUEST_INVALID"), "functional_failure"),
        (Scenario("A", "a", "allow"), Observation("deny", "SIGNATURE_INVALID"), "functional_failure"),
        (Scenario("A", "a", "allow"), Observation("allow", None, True), "pass"),
        (Scenario("C", "c", "at_most_one_allow"), Observation("multi", allows=1, attempts=16), "pass"),
        (Scenario("C", "c", "at_most_one_allow"), Observation("multi", allows=2, attempts=16), "security_failure"),
        (Scenario("C", "c", "at_most_one_allow"), Observation("multi", allows=0, attempts=16), "functional_failure"),
        (Scenario("R", "r", "reject", ("REQUEST_INVALID",)), Observation("allow", None), "security_failure"),
    ],
)
def test_classification_rules(scenario, obs, outcome):
    assert classify(scenario, obs)[0] == outcome


def test_crashing_scenario_is_infrastructure_failure():
    def boom(_driver):
        raise RuntimeError("harness broke")

    r = run_scenario(Scenario("X", "crash", "deny", (), boom))
    assert r.outcome == "infrastructure_failure"
    assert "harness broke" in r.note
    assert r.observed is None
