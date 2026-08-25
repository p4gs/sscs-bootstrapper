# Files

- [Adding a control](adding-a-control.md) - The files a new control must touch, the tests that enforce each requirement, and the gaps the contract does not cover.
- [Compliance mapping and sscsb report](compliance-mapping.md) - How controls map onto SLSA, SSDF, CRA and the OpenSSF frameworks, and precisely what the report does and does not assert.
- [Configuration and the off-means-off contract](configuration.md) - How .sscsb/config.toml is generated and read, what happens to absent, wrong-typed and unknown keys, and the limits of disabling a control.
- [The five-phase model](phases.md) - How sscsb bands its 44 controls into five phases, where phases are enforced, and where they are only conventional.
- [The control registry and the verdict contract](registry-and-outcomes.md) - How sscsb decides what a control concluded, what each of the five verdicts means, and how verdicts become process exit codes.
- [What sscsb writes to your repository](repository-state.md) - The per-path on-disk contract — which files are kept, which are regenerated every run, and which are extended.
