"""Attack Lab endpoints. The only route module allowed to reach app.lab (D-005)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import insert, select

from app.errors import ApiError
from app.lab.scenarios import SCENARIOS, run_scenario
from app.models.schemas import ErrorResponse, LabRun, LabRunList, ScenarioCatalog, ScenarioResult, ScenarioSummary
from app.models.tables import lab_runs
from app.routes.labs import require_lab
from app.security.encoding import new_id
from app.security.events import record_event

router = APIRouter(prefix="/api/labs")

MAX_RUNS_LISTED = 50


@router.get("/{lab_id}/scenarios", response_model=ScenarioCatalog, responses={404: {"model": ErrorResponse}})
def list_scenarios(lab_id: str = Depends(require_lab)) -> ScenarioCatalog:
    return ScenarioCatalog(
        scenarios=[ScenarioSummary(id=s.id, title=s.title, description=s.description, expected=s.expected) for s in SCENARIOS.values()]
    )


@router.post("/{lab_id}/scenarios/{scenario}", response_model=ScenarioResult, responses={404: {"model": ErrorResponse}})
def post_scenario(scenario: str, request: Request, lab_id: str = Depends(require_lab)) -> ScenarioResult:
    """Run a predefined scenario on disposable state. The lab's own vehicles, keys and challenges are untouched."""
    if scenario not in SCENARIOS:
        raise ApiError(404, "SCENARIO_NOT_FOUND", "Unknown scenario")
    state = request.app.state
    now = state.clock()
    result = run_scenario(scenario, now=now)
    run_id = new_id("run")
    with state.engine.begin() as conn:
        for run in result["runs"]:
            conn.execute(
                insert(lab_runs).values(
                    id=f"{run_id}-{run['mode'][0]}",
                    lab_id=lab_id,
                    scenario=scenario,
                    mode=run["mode"],
                    expected_result=result["expected"][run["mode"]],
                    actual_result=run["attack_decision"],
                    actual_reason=run["attack_reason"],
                    duration_ms=result["duration_ms"],
                    created_at=now,
                )
            )
        record_event(
            conn, lab_id=lab_id, event_type=f"scenario_{scenario}",
            outcome="as_expected" if result["matches_expected"] else "unexpected",
            duration_ms=result["duration_ms"], now=now,
        )
    return ScenarioResult(run_id=run_id, created_at=now, **result)


@router.get("/{lab_id}/lab-runs", response_model=LabRunList, responses={404: {"model": ErrorResponse}})
def get_lab_runs(request: Request, lab_id: str = Depends(require_lab)) -> LabRunList:
    with request.app.state.engine.connect() as conn:
        rows = conn.execute(
            select(lab_runs).where(lab_runs.c.lab_id == lab_id).order_by(lab_runs.c.created_at.desc(), lab_runs.c.id).limit(MAX_RUNS_LISTED)
        ).mappings()
        return LabRunList(
            runs=[
                LabRun(
                    run_id=r["id"].rsplit("-", 1)[0], scenario=r["scenario"], mode=r["mode"],
                    expected_result=r["expected_result"], actual_result=r["actual_result"],
                    actual_reason=r["actual_reason"], duration_ms=r["duration_ms"], created_at=r["created_at"],
                )
                for r in rows
            ]
        )
