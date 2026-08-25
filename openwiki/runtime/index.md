# Files

- [External tools, detection and degradation](external-tools-and-degradation.md) - How sscsb pins tool versions, what makes a binary count as installed, and why a decoy on PATH no longer satisfies a control.
- [Process execution and the tool exit-code contract](process-execution.md) - How sscsb invokes external tools, why a killed scanner must not read as a clean one, and the argument-injection guard on git.
- [Repository context](repository-context.md) - How sscsb finds the repository it is operating on, resolves the slug and default branch, and where it guesses.
