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

Follow-up worth doing properly: have the test helpers (`test_repo()` /
`exec::git` under `cfg(test)`) set this isolation themselves so the suite is
hermetic by construction rather than by invocation discipline.

<!-- OPENWIKI:START -->

## OpenWiki

See [AGENTS.md](AGENTS.md) for OpenWiki agent instructions.

<!-- OPENWIKI:END -->
