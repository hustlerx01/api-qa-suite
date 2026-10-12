"""OWASP API Security Top 10 (2023) checks. Each test names the category it covers."""
from tests.conftest import ALICE, BOB

def test_API1_BOLA_cannot_read_other_users_object(client):
    r = client.get("/tasks/1", headers=BOB)          # task 1 belongs to alice
    assert r.status_code in (403, 404), f"BOLA: bob read alice's task -> {r.status_code} {r.text}"

def test_API2_forged_token_rejected(client):
    r = client.get("/me", headers={"Authorization": "Bearer tok-forged-xyz"})
    assert r.status_code == 401, f"forged token accepted as {r.json()}"

def test_API2_malformed_auth_header(client):
    import httpx
    for h in ["tok-alice", "Basic tok-alice", "Bearer ", "bearer tok-alice"]:
        try:
            assert client.get("/me", headers={"Authorization": h}).status_code == 401, h
        except httpx.LocalProtocolError:
            pass   # real httpx refuses to send a header with trailing whitespace: nothing reached the server

def test_API3_no_sensitive_fields_exposed(client):
    body = client.get("/me", headers=ALICE).json()
    leaked = {k for k in body if any(s in k.lower() for s in ("pw", "password", "hash", "secret", "token"))}
    assert not leaked, f"sensitive fields exposed: {leaked}"

def test_API3_mass_assignment_owner_id(client):
    r = client.post("/tasks", json={"title": "sneaky", "owner_id": 2}, headers=ALICE)
    assert r.status_code == 422 or r.json()["owner_id"] == 1, f"mass assignment: owner_id={r.json().get('owner_id')}"

def test_API4_rate_limiting(client):
    codes = [client.get("/tasks", headers=ALICE).status_code for _ in range(60)]
    assert 429 in codes, "no rate limiting after 60 requests in <10s"

def test_API8_security_headers(client):
    h = client.get("/tasks", headers=ALICE).headers
    missing = [k for k in ("x-content-type-options", "cache-control") if k not in h]
    assert not missing, f"missing headers: {missing}"
    assert "x-powered-by" not in h, f"version disclosure: {h.get('x-powered-by')}"

def test_API8_no_stack_trace_on_bad_input(client):
    r = client.get("/tasks/abc", headers=ALICE)
    assert r.status_code == 422 and "Traceback" not in r.text

def test_injection_payloads_are_data(client):
    for p in ["' OR 1=1--", "<script>alert(1)</script>", "{{7*7}}", "../../etc/passwd"]:
        r = client.post("/tasks", json={"title": p}, headers=ALICE)
        assert r.status_code == 201 and r.json()["title"] == p
