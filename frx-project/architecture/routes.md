# FRX Route and Entry-Point Inventory

Instructor reference; excluded from the learner package. Both states expose the methods and paths below, but some input contracts and security decisions differ. E3 in [`materials/system-evidence.md`](../../materials/system-evidence.md) supplies the learner-facing interface handoff without solution details.

| Method and route | Inputs | Implemented behavior and review scope |
|---|---|---|
| `GET /` | None | Browser client for the ordinary FRX workflow. It calls the existing login, search, report-detail, analytics-fetch and document-intake routes and renders returned values as text. |
| `GET /health` | None | Public response with service, selected state and status. |
| `POST /login` | Username/password as JSON or form fields | Credential lookup and verification, session creation, audit events. Query construction, password storage, active-account handling and logging differ by state. |
| `POST /logout` | Session cookie, when present | Logs logout and clears the session. Does not require an authenticated caller. |
| `GET /welcome` | `name` query value | Public HTML greeting. Vulnerable state interpolates input; remediated state uses template encoding. |
| `GET /reports/<report_id>` | Session and integer path ID | Retrieves a preloaded report. Vulnerable state checks authentication only; remediated state checks ownership, analyst assignment or administrator role. Both return report data or an error and record selected read outcomes. |
| `GET /search` | Session and `q` query value | Searches titles and summaries. Remediated state bounds query length, parameterizes SQL and filters returned rows through the report-access rule. Neither state audits this route. |
| `POST /documents` | Session and multipart `document` file | Stores a standalone file and returns its stored name. Vulnerable state uses the client basename and allows overwrites; remediated state constrains extensions/content and generates a filename. Both confine writes to the upload store. No report association, ownership record or retrieval is implemented. |
| `POST /analytics/import` | Session and request body | Vulnerable state inspects base64-encoded pickle opcodes without execution. Remediated state accepts JSON with permitted fields and checks required field types. Both return processing results without persistence; neither applies report ownership checks to an imported report identifier. |
| `GET /analytics/fetch` | Vulnerable: session and `url`; remediated: session and `report_id` | Vulnerable state accepts a URL on the configured local fixture origin. Remediated state checks report access and constructs `/metrics/<report_id>` on that origin, handles provider failure and validates returned report identity. |
| `GET /errors/demo` | Session | Deliberately generated diagnostic failure. Vulnerable state exposes internal details; remediated state emits a generic response and audit event. Also inspect application-level error handlers for other failures. |

The application applies a request-size limit from its settings in both states. File validation and request-size limits do not establish report authorization or complete file-intake governance.

## Scope and dependency limits

There are no report creation, editing, deletion, assignment-change or approval routes. Uploaded files have no download/list/delete routes or report relationship. Import does not add analytics data to the database. These limits must remain explicit when translating Day 1 requirements into Day 2 verification.

The analytics fixture exposes `GET /health` and `GET /metrics/<report_id>`. Metrics return a report ID, deterministic score, category and source; the fixture does not read FRX records. The case assigns the score a manual prioritization role, with review able to continue when it is unavailable. Keep the fixture unmodified and all services on loopback for exercises.

## Review change points

- Authentication/session: state blueprint `login`, `logout` and app configuration; inspect credential handling, session state, cookie options, active-account behavior and audit output.
- Report access and search: `report_detail`, `search` and remediated `_can_read`; compare permitted and denied identities across entry points.
- File intake: `upload_document`, `_valid_upload` and application request-size settings; check naming, content, overwrite behavior and confined storage. Report-scoped ownership would require a feature change.
- Analytics: `analytics_import` and `analytics_fetch`; distinguish parsing/validation from authorization, persistence and the outbound request contract.
- Persistence/reset: `database.py`; reconcile seed IDs, report owners and analyst assignments with the evidence packet.
- Error/audit behavior: app error handlers and state audit helpers; inspect event coverage and information disclosure separately.
