# sscs-bootstrapper — project rules

## Running the test suite from an agent shell

The suite creates real git repos and verifies real SSH signatures, so it is
only hermetic when the host's git identity cannot leak into the fixtures. Two
leaks both manifest as mass `status U` / "communication with agent failed"
test failures that look like code regressions and are not:

- The agent harness injects `GIT_CONFIG_KEY_n/VALUE_n` (`user.signingkey`,
  `commit.gpgsign`, `user.email`) at `command line` scope, which beats every
  repo-local `git config` the fixtures set — test commits get signed by the
  agent key and authored as the agent.
- With that neutralized, the global `~/.gitconfig` (`commit.gpgsign = true` +
  the human's Secure-Enclave key) applies instead, and fixtures that never
  configured signing try to sign through an agent that cannot tap.

Always run tests as:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
```

Follow-up worth doing properly: have the test helpers (`test_repo()` /
`exec::git` under `cfg(test)`) set this isolation themselves so the suite is
hermetic by construction rather than by invocation discipline.
