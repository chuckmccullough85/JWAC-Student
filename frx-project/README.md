# Field Research Exchange learner project

The student lab guide PDF contains the system evidence packet and Day 2 source orientation for this project. Use the stable baseline identifier `FRX-LEARNER-BASELINE` in the retained review record.

This project contains only the deliberately vulnerable learner state. Run setup, the analytics fixture, the portal, and reset through the scripts at the package root. Both services are constrained to loopback and use synthetic data.

`tests/conftest.py` is included only because the frozen Lab 4 report bundle binds that learner-safe fixture as a scanned source input. No executable test cases, remediated implementation, or solution assertions are included.

The browser client supports sign-in, report search and reading, analytics requests, and document intake. Treat source, runtime observations, controlled criteria, and later decision records according to the boundaries in the student lab guide; do not infer intended policy merely because the application behaves a particular way.
