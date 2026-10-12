"""Suite runs in-process (ASGI) by default; set BASE_URL to test a deployed instance instead."""
import importlib, os
import httpx, pytest

def load_app():
    import api.app as m
    importlib.reload(m); return m

@pytest.fixture
def mod():
    m = load_app(); m.reset(); return m

@pytest.fixture
def client(mod):
    base = os.getenv("BASE_URL")
    if base:
        with httpx.Client(base_url=base) as c:
            c.post("/__test/reset")   # server must run with ALLOW_TEST_RESET=1
            yield c
    else:
        from fastapi.testclient import TestClient
        with TestClient(mod.app) as c: yield c

ALICE = {"Authorization": "Bearer tok-alice"}
BOB = {"Authorization": "Bearer tok-bob"}
ADMIN = {"Authorization": "Bearer tok-admin"}
