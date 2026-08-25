# Files

- [AI provenance trailers and the commit gates](ai-provenance-trailers.md) - What an AI-assisted commit must declare, the review gates that follow from it, and what a pre-push hook can honestly prove.
- [The git hook engine](git-hooks.md) - How sscsb installs three hooks, why the shims are dumb on purpose, and how staged content is materialised for scanning.
- [gittuf ref policy](gittuf-ref-policy.md) - A signed, forge-independent policy over who may change which refs, and why this control is careful about what Pass means.
- [The server-side policy gate](server-side-policy-gate.md) - The enforcement that survives an attacker-controlled working tree, and the agent-signing control that installs it.
- [Signer policy and the client-side gate](signer-policy.md) - The three signer classes, how allowed_signers is derived, and the half of the AI-cannot-sign invariant that runs on your machine.
- [The five signing environments](signing-environments.md) - Where a commit can come from, who signs in each case, and how sscsb handles the environments it cannot probe.
