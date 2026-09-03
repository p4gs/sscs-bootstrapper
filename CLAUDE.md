# sscs-bootstrapper — project rules

## Running the test suite from an agent shell

The suite creates real git repos and verifies real SSH signatures, so it is
only hermetic when the host's git identity cannot leak into the fixtures.
Three leaks all look like code regressions and are not — the first two
manifest as mass `status U` / "communication with agent failed" test
failures, the third as a suite that simply never finishes:

- The agent harness injects `GIT_CONFIG_KEY_n/VALUE_n` (`user.signingkey`,
  `commit.gpgsign`, `user.email`) at `command line` scope, which beats every
  repo-local `git config` the fixtures set — test commits get signed by the
  agent key and authored as the agent.
- With that neutralized, the global `~/.gitconfig` (`commit.gpgsign = true` +
  the human's Secure-Enclave key) applies instead, and fixtures that never
  configured signing try to sign through an agent that cannot tap.
- `SSH_AUTH_SOCK` points at that same Secure-Enclave / 1Password agent, which
  answers a signature request only after a physical tap on the human's
  hardware. Any fixture that still reaches it therefore blocks on a prompt
  nobody is watching: the run does not fail, it hangs — observed at 40+
  minutes — and an agent shell reads that as a slow test suite rather than a
  wedged one. Unsetting the variable makes the same request fail in
  milliseconds with a message, which is the outcome you want from a leak.

Always run tests as:

```sh
SSH_AUTH_SOCK= GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
```

There is a fourth leak that the command above does **not** cover, because it
comes from PATH rather than from git config. A fixture that calls
`init::bootstrap()` points `core.hooksPath` at the installed shims, and the
pre-commit shim fail-closes when the `sscsb` CLI is not on PATH — correct
product behaviour, and the state of every fresh CI runner. On a developer
machine `sscsb` *is* on PATH, so such a fixture passes locally and fails only
in CI. Every fixture commit must therefore pass `--no-verify` (the convention
already used in `signers`, `hooks`, `openssf`, `deps`, `provenance`); the shims
have their own tests, and a fixture's setup commit is scaffolding, not subject.

To reproduce a CI runner locally, hide **only** `sscsb` and keep every other
tool. Do not simply drop `/opt/homebrew/bin` from PATH: `cosign`, `semgrep`,
`slsa-verifier` and `gitleaks` live there too, CI installs them, and removing
them manufactures 10 unrelated failures in `hooks`, `provenance` and `sast`
that will send you chasing the wrong bug. Shadow the directories with a
symlink farm instead:

```sh
FARM="$(mktemp -d)/bin"; mkdir -p "$FARM"
for d in /opt/homebrew/bin "$HOME/.cargo/bin"; do
  for f in "$d"/*; do b="$(basename "$f")"
    [ "$b" = sscsb ] && continue; [ -e "$FARM/$b" ] && continue; ln -s "$f" "$FARM/$b"
  done
done
REST="$(printf '%s' "$PATH" | tr ':' '\n' | grep -vxF /opt/homebrew/bin | grep -vxF "$HOME/.cargo/bin" | paste -sd: -)"
PATH="$FARM:$REST" SSH_AUTH_SOCK= GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
```

Sanity-check the farm with `command -v sscsb` (must print nothing) and
`command -v cosign` (must print a path) before trusting a run. This caught 18
real failures in `local_scan` that a normal local run reported as green.

Follow-up worth doing properly: have the test helpers (`test_repo()` /
`exec::git` under `cfg(test)`) set this isolation themselves so the suite is
hermetic by construction rather than by invocation discipline.

<!-- OPENWIKI:START -->

## OpenWiki

See [AGENTS.md](AGENTS.md) for OpenWiki agent instructions.

<!-- OPENWIKI:END -->
