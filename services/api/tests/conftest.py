import sys
from pathlib import Path

import pytest

# Make `app` and the test helpers importable without packaging the service.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

NOW = 1_793_923_200


class Clock:
    def __init__(self, t: int) -> None:
        self.t = t

    def __call__(self) -> int:
        return self.t


@pytest.fixture
def clock():
    return Clock(NOW)


@pytest.fixture
def client(tmp_path, clock):
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(f"sqlite:///{tmp_path / 'kg.db'}", clock=clock)
    with TestClient(app) as c:
        yield c
    app.state.engine.dispose()


@pytest.fixture
def new_lab(client):
    """Create a lab over HTTP; returns its JSON plus auth headers and the seeded vehicle ID."""
    lab = client.post("/api/labs").json()
    headers = {"Authorization": f"Bearer {lab['lab_token']}"}
    vehicle_id = client.get(f"/api/labs/{lab['lab_id']}/vehicles", headers=headers).json()["vehicles"][0]["id"]
    return {**lab, "headers": headers, "vehicle_id": vehicle_id}
