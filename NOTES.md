# Interview talking points: api-qa-suite
1. **A suite needs teeth.** CI runs the suite against a deliberately vulnerable build and *requires* 9 failures. If someone weakens an assertion, CI goes red. This is mutation-testing thinking applied to security checks.
2. **BOLA is #1 for a reason.** It's just changing `/tasks/1` to `/tasks/2`. The fix returns 404, not 403, so it doesn't confirm the object exists.
3. **Property-based contract testing finds what humans don't.** schemathesis found 0 coerced to false, a wrong Allow header, and undocumented 400/429 codes. None were on my list.
4. **Test pyramid.** Fast in-process ASGI tests (about 2 s) on every PR. The same tests run against a live container via `BASE_URL`. ZAP runs nightly.
5. **Flakiness I hit.** Shared state plus the rate limiter made live tests order-dependent. I fixed it with an explicit reset hook that's disabled by default, and I'd never ship it enabled.
6. **Boundaries and i18n.** Title lengths 0/201, an invalid enum, and Hindi plus emoji input. Indian products must handle Devanagari.
7. **Mass assignment.** `extra="forbid"` rejects unknown fields (422) instead of silently dropping or honouring them.
