# Files

- [Branch protection, read and write](branch-protection.md) - The verifier and its write-side counterpart, why some gaps fail the control and others only report, and what harden refuses to do.
- [CI hardening controls](ci-hardening.md) - Runner hardening checked per job, the one control whose verdict is a constant, and the shape machinery every template control shares.
- [Federated credentials](federated-credentials.md) - Replacing long-lived tokens with short-lived, scope-limited ones exchanged from a workflow's own identity — and the limit of what sscsb verifies about the policy.
- [Scorecard integration](scorecard.md) - Reading live Scorecard findings, routing each to the control that owns it, and why open findings are informational rather than failing.
- [Workflow auditing](workflow-auditing.md) - How sscsb audits GitHub Actions workflows for pinning and least privilege, and the calibration behind each threshold.
