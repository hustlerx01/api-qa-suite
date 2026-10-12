"""Property-based contract testing from the OpenAPI schema (schemathesis)."""
import schemathesis
from hypothesis import settings, HealthCheck
import api.app as m

schema = schemathesis.openapi.from_asgi("/openapi.json", m.app)

@schema.parametrize()
@settings(max_examples=25, deadline=None, suppress_health_check=list(HealthCheck))
def test_api_conforms_to_schema(case):
    m.reset()
    case.call_and_validate(headers={"Authorization": "Bearer tok-admin"})
