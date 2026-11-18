# Official OpenGrep Agent Skill

`SKILL.md` and `LICENSE` are unmodified copies from
https://github.com/opengrep/skills/tree/bfbc2419225e8884a343c312b2d3b05c2106fa45
(retrieved 2026-11-16). They are the skill distributed by
`npx skills add opengrep/skills` (or `bunx skills add opengrep/skills`).

SHA-256:

- `SKILL.md`: `aa747516f4b5d1333a5f5e015de7723501ac944be0743b92e1e844dcf376ad42`
- `LICENSE`: `a75e3644ee738d8e56909f919b7e2a3c3108812f3cef95253aae9d593492b520`

`sscsb init` installs these bytes for Claude Code and Agent Skills-compatible
clients when `sast` is enabled, preserving existing files. Bundling the pinned
source keeps bootstrap offline and avoids executing a package-manager download.
Upstream examples of scanner suppressions describe OpenGrep syntax; repository
policy still governs their use.
