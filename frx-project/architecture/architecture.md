# Field Research Exchange Architecture

Instructor reference; excluded from the learner package. E1–E6 in [`materials/system-evidence.md`](../../materials/system-evidence.md) are the canonical case evidence. The separate `data-flow.mmd` is a connectivity sketch, not a completed threat model.

## Purpose and deployment evidence

FRX supports review of partner field observations before a weekly planning meeting. The current assignment concerns expansion from two partner organizations to twelve in six weeks. Partners should read their own registered reports, analysts their assigned reports, and administrators the collection for troubleshooting. These are requirements to check against implementation.

E3 establishes the supplied local architecture and states that no separate gateway, identity provider, queue, or deployed network segmentation is evidenced. Managed intake supplies registered records and assignment metadata outside the portal. Network enforcement, service privileges and monitoring remain unverified. Do not infer a separate security boundary from a component label.

The supplied runtime is one Flask portal process bound to loopback, with SQLite, file intake and event-log files under its state directory. A second local Flask process represents the analytics provider. There is no separately implemented gateway appliance, network segment or enterprise identity service.

## Component responsibilities

| Component | Current responsibility | Runtime representation |
|---|---|---|
| Browser/API client | Sends credentials, session cookies, report identifiers, search text, uploads and analytics requests; receives responses. | Browser, HTTP client or Flask test client. |
| Portal | Handles sessions and routes, queries records, writes intake files and selected audit events, requests analytics. | `frx_portal.app.create_app` and the selected state blueprint. |
| Identity/report store | Holds users and three preloaded reports with owner and analyst-assignment fields. | State-specific SQLite database. |
| File intake store | Holds uploaded files; returns a stored filename to the caller. | State-specific upload directory. |
| Event log | Records selected authentication, report, upload, analytics or error events, depending on the state and route. | State-specific UTF-8 file. |
| Analytics provider | Returns a report identifier and score; has no direct records-store connection. | `fixture_service.py` on loopback. |
| Managed intake and registration | Registers report contents, owner and analyst assignment outside the portal under E2. | External case dependency; no registration/assignment interface is implemented in this build. |

## Scope limits that affect the model

Reports are registered and assigned through a separate coordinator-managed process described in E2; those operations are outside the reviewed build. A successful report lookup is not a registration acknowledgment. The application has no report creation, editing, assignment-change or approval routes.

File intake does not accept a report identifier, store an uploader/report relationship, or expose file retrieval. Treat association and retrieval as planned work. Do not narrate an implemented upload-to-report-to-reviewer lifecycle.

Analytics import examines submitted data and returns a result without storing it. The remediated import validates expected JSON fields but does not check ownership of its `report_id`. Analytics fetch is a separate operation: its remediated path checks report access before requesting a score. Neither route represents automatic report release or approval; E2 defines report access and E5 says review can continue without a score.

E4 requires report reading to remain available when analytics is unavailable, and E5 makes the score advisory. Provider timeout/failure behavior and shared-capacity effects still require engineering evidence under an owner-supplied load profile; the packet provides no such profile.

The audit file does not establish complete event coverage, central monitoring or tamper protection. E4 states that acknowledged intake documents must not be lost, permits an interruption of up to two hours with notice, and says restore capability has not been demonstrated. Backup scope, restore consistency, timing and monitoring need evidence beyond the runtime.

## Boundary reasoning for facilitation

Ask what authority, control or ownership changes along each flow. Client-to-portal data, report access under a session identity, persistent file writes and communication with the analytics provider are useful places to investigate. Separately named stores do not prove independently enforced zones: the portal process accesses the database, upload directory and audit file directly. A learner may place different logical boundaries if the justification and required enforcement evidence are clear.

Learner/instructor packaging is a course-production control, not a component of the FRX operational system. Keep package separation in setup and production documentation.

## Representative implemented request

For `GET /reports/101`:

1. A client sends a session cookie and report identifier to the portal.
2. The state blueprint checks for a session identity and reads the matching report row.
3. The vulnerable state returns an existing row to any authenticated user and logs the read.
4. The remediated state returns the row only to its owning partner, assigned analyst or an administrator, and logs the successful or denied authorization outcome.
5. The response contains report JSON or an error. A nonexistent report returns a not-found response.

This path supports Day 2 review of session identity, object authorization, persistence, response data and audit evidence. It does not imply that equivalent controls cover every route. In particular, vulnerable login events include passwords; the report-read example is not evidence of safe logging throughout the application.

## Instructor containment

Keep both application states and the unmodified analytics fixture on loopback with supplied synthetic data. The fixture is not an operational service. Upload paths are confined to disposable runtime storage, serialized input is inspected without executing it, and outbound destinations are constrained to the configured local fixture origin. Preserve these limits during demonstrations and resets.

The two states have separate databases and runtime directories. Learner packages exclude the remediated source, solution-oriented tests and this instructor reference. Enterprise authentication, deployment segmentation, production TLS termination and recovery infrastructure require evidence beyond this build.
