import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ADMIN_PASSWORD", "test-password-1234")
    monkeypatch.setenv("ACCESS_LOG", str(tmp_path / "no-such-access.log"))
    from app import main
    importlib.reload(main)
    monkeypatch.setattr(main, "apply_config", lambda: None)
    with TestClient(main.app, base_url="http://localhost") as c:
        yield c


@pytest.fixture
def client_with_store(client):
    from app import main
    client.post("/login", json={"password": "test-password-1234"})
    return client, main.store
