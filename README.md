# Threat Modeling and Secure Code Review — student package

This is the standalone learner repository for the two-day workshop. Start with the PDF slide deck and keep one Field Research Exchange (FRX) review record through both days.

## Package map

- [Slide deck](presentation/course.pdf)
- [Student lab guide](labs/student-lab-guide.pdf), including the evidence packet, diagram collection, notation lesson, and supporting reference appendices
- [Day 1 editable record workbook](labs/day-1-record-templates.docx)
- [Day 2 editable record workbook](labs/day-2-record-templates.docx)
- [FRX learner project](frx-project/README.md)
- `materials/architecture/rendered/` — full-resolution PNG and SVG diagram copies
- `labs/day-2/` — bounded observation, evidence-bundle, and remediation-review support files

## Local setup

Use PowerShell 7.4 or later from the extracted package root. Python 3.12 is the learner baseline. The root [requirements.txt](requirements.txt) contains the pinned virtual-environment modules.

```pwsh
./scripts/setup.ps1
./scripts/verify-environment.ps1
./scripts/run-fixture-service.ps1
```

In a second terminal:

```pwsh
./scripts/run-portal.ps1
```

Open `http://127.0.0.1:5100/`. Stop the portal before resetting:

```pwsh
./scripts/reset-lab.ps1
```

The project contains deliberate weaknesses and synthetic data for local defensive training. Keep both services on loopback. Never expose them publicly or enter operational credentials or information.

## Governed inputs and distribution boundary

The authorized code-review checklist and APPROVE template are supplied separately by the instructor when their governed workflows begin. They are not embedded here.

Lab 5 uses bounded proposed-change excerpts. The complete remediated reference source and solution-oriented tests remain instructor-only. The instructor prepares the proposed-state proof workspace before Lab 5; the packaged runner and change catalog in the lab-guide appendix identify the baseline, integrity checks, and evidence limits.

This repository excludes complete solutions, instructor runbooks, remediated source, solution-oriented tests, development QA, the candidate exam export, the raw customer checklist, and the raw APPROVE template.
