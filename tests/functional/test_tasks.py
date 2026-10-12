import pytest
from tests.conftest import ALICE, BOB, ADMIN

def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}

@pytest.mark.parametrize("path", ["/me", "/tasks", "/tasks/1"])
def test_auth_required(client, path):
    assert client.get(path).status_code == 401

def test_create_and_get(client):
    r = client.post("/tasks", json={"title": "write tests", "priority": "high"}, headers=ALICE)
    assert r.status_code == 201
    t = r.json(); assert t["owner_id"] == 1 and t["done"] is False
    assert client.get(f"/tasks/{t['id']}", headers=ALICE).json()["title"] == "write tests"

def test_list_only_own(client):
    titles = [t["title"] for t in client.get("/tasks", headers=BOB).json()]
    assert titles == ["bob task"]

def test_admin_sees_all(client):
    assert len(client.get("/tasks", headers=ADMIN).json()) == 2

@pytest.mark.parametrize("body,code", [({"title": ""}, 422), ({"title": "x" * 201}, 422),
                                       ({"title": "ok", "priority": "urgent"}, 422), ({}, 422),
                                       ({"title": "नमस्ते 🚀"}, 201)])
def test_validation_boundaries(client, body, code):
    assert client.post("/tasks", json=body, headers=ALICE).status_code == code

def test_delete_other_users_task_is_404(client):
    assert client.delete("/tasks/2", headers=ALICE).status_code == 404
    assert client.delete("/tasks/2", headers=BOB).status_code == 204
    assert client.get("/tasks/2", headers=BOB).status_code == 404
