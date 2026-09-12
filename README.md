# DummyJSON API Security & RBAC Automation Framework

A data-driven API security test framework targeting the public DummyJSON sandbox
(`https://dummyjson.com`), covering authentication, token/session handling,
role-based authorization, resource ownership, and sensitive data exposure.

> **Target limitation.** DummyJSON is a public sandbox and does not implement a
> production-grade authorization model. This suite deliberately separates
> **documented API contract behaviour** from **stated production security
> expectations**, so that a gap between the two is reported as a *security
> finding* rather than hidden or silently "fixed" by relaxing the assertion.

---

## 1. Installation

**Prerequisites**
- Java 21 (JDK)
- Maven 3.9+
- Internet access to `https://dummyjson.com` (no credentials required — see
  Assumptions)

```bash
git clone <repo-url>
cd dummyjson-api-security
mvn -q dependency:resolve
```

No API keys, tokens, or `.env` files are required. `src/main/resources/config.properties`
holds the only environment-specific value (`base.url`), and it can be
overridden without touching source:

```bash
mvn test -Dbase.url=https://dummyjson.com
```

## 2. Execution

Run the full suite (TestNG, driven by `testng.xml`):

```bash
mvn clean test
```

> **Note on runtime:** one test (`AUTH-005`, expired-token validation) sleeps
> for real for ~65 seconds to allow a short-lived token to genuinely expire,
> rather than mocking time. This is a deliberate trade-off — see *Limitations*.

Generate and view the Allure report after a run:

```bash
mvn allure:report
mvn allure:serve
```

Allure results are cleaned automatically at the start of each suite run
(`AllureReportCleaner`) so reports never mix data from different executions.

Logs are written to `logs/security-automation.log`. Authorization headers,
tokens, and passwords are redacted before anything is logged (see
`ApiClient#sanitize`).

## 3. Architecture

```
src/main/java/com/qa/security/
  client/          ApiClient — low-level HTTP wrapper (RestAssured), request/response
                   logging with credential redaction, no test-framework dependency
  services/        AuthService, UserService — one class per API resource area
  models/          Request/response POJOs (Jackson + Lombok)
  assertions/      ApiAssertions — generic, reusable status/field assertions
  constants/       Endpoint paths and HTTP status codes, single source of truth
  config/          ConfigManager — loads base.url, no secrets in code

src/test/java/com/qa/security/
  client/          AuthContextFactory (per-role token cache) and
                   TestUserResolver (maps role keys -> real DummyJSON credentials)
  matrix/          SecurityMatrixRow, MatrixContext (runtime {{placeholder}}
                   resolution), SecurityMatrixProvider (loads matrix JSON as a
                   TestNG DataProvider)
  test/            BaseSecurityTest (shared execution/reporting engine),
                   SecurityMatrixTest (data-driven), AuthenticationSecurityTest
                   (scenarios that don't fit the matrix shape: anonymous access,
                   invalid token, expired token)
  utils/           AllureTestReporter, SecurityFindingReporter — turn a matrix
                   row + actual result into structured Allure evidence

src/test/resources/matrix/security-matrix.json   — the security matrix itself
```

**Why a data-driven matrix instead of one method per case:** roles, endpoints,
methods, and expected outcomes are pure data. Adding a new authorization
scenario means adding a JSON row, not writing a new test method — this is what
the brief calls out as "reusable, maintainable, extensible."

**Why `expectationType` exists:** every matrix row is classified as one of:
- `DOCUMENTED_CONTRACT` — behaviour explicitly documented by DummyJSON; a
  mismatch is a genuine automation/contract bug.
- `SECURITY_HYPOTHESIS` / `SECURITY_EXPECTATION` — behaviour DummyJSON does
  not document but a production system should enforce; a mismatch is reported
  as a **security finding** (Allure attachment + failed test), not silently
  passed or silently ignored.

This distinction is what lets the suite fail loudly on real authorization
gaps without pretending DummyJSON is non-compliant with a spec it never made.

## 4. Test Strategy

Priorities were driven by the security intent in the brief, roughly in this
order:

1. **Authentication boundary** — can protected endpoints be reached
   unauthenticated, with an invalid token, or with an expired token?
   (`AUTH-001/003/005`)
2. **Identity correctness** — does `/auth/me` return the identity that was
   actually authenticated, not some other user's? (`AUTH-004`)
3. **Resource ownership (BOLA)** — can one standard user read/modify/delete
   another user's resource? (`OWN-001/002`, `RBAC-001/002/003`)
4. **Role escalation** — can a standard user or moderator perform an
   admin-level action, or elevate their own role? (`RBAC-004/005`)
5. **Safe failure** — does a non-existent resource fail without leaking
   internal detail? (`NEG-001`)
6. **Sensitive data exposure** — does a legitimate, authorized response still
   leak fields like passwords, bank details, or MAC addresses? (`EXP-001`)

Each row's `rationale` field states *why* that outcome is expected, and
`owaspCategories` maps it to OWASP API Security Top 10 (2023) so a security
stakeholder can scan the matrix without reading test code.

## 5. Assumptions

- Test user credentials are **not** supplied and are **not** hardcoded. They
  are resolved at runtime from the public `/users` directory, grouped by the
  `role` field DummyJSON exposes (`admin` / `moderator` / `user`).
- A standard user should not be able to view, modify, or delete another
  user's resource, and should not be able to change their own or another
  account's `role` — these are stated as production security expectations,
  not asserted as documented DummyJSON behaviour.
- `PATCH`/`DELETE` responses from DummyJSON are simulated and are not
  expected to persist; assertions target the HTTP status and response shape
  of that single call, not follow-up state.

## 6. Limitations / Incomplete areas

- **Token/session handling is only partially covered.** `/auth/refresh` is
  defined as a constant but has no test coverage — refresh-token reuse across
  roles and refresh-token expiry semantics are untested.
- **No JSON schema/contract validation** beyond status codes and the fixed
  sensitive-field list — response shape/type drift on `/auth/me` or
  `/users/{id}` would not currently be caught.
- **Boundary/negative coverage is thin** — one case (non-existent ID).
  Malformed body, wrong `Content-Type`, and non-numeric/negative IDs are not
  covered.
- **No explicit resilience handling** — `ApiClient` does not set connection/
  read timeouts, so a hung request would stall the suite rather than fail
  fast.
- **`AUTH-005` takes ~65 real seconds** (genuine token-expiry wait, not a
  load/stress test) — this is a deliberate trade-off to avoid mocking time,
  but it means the suite is not "fast" end-to-end. It is not currently
  isolated into a separate/optional TestNG group.
- **Unauthenticated bulk data exposure is not asserted.** DummyJSON's public
  `/users` and `/users/{id}` endpoints return plaintext passwords and
  financial fields to *anonymous* callers with no authentication at all —
  the framework's own `TestUserResolver` relies on this to bootstrap test
  credentials, but no matrix row currently turns this into an explicit,
  reported finding. This is arguably the most significant exposure available
  on this target and should be the next case added.

## 7. Actual effort spent

<!-- TODO: fill in honestly, e.g. "~X hours over Y days: Z hrs framework
     skeleton, Z hrs matrix design, Z hrs reporting/Allure integration" -->

## 8. AI-assisted development disclosure

<!-- TODO: name the tool(s) used, what they were used for (e.g. boilerplate
     generation, refactoring, matrix row drafting), and how the output was
     reviewed/validated before inclusion. Required by the brief regardless
     of whether AI tools were used at all — state "none used" if applicable. -->