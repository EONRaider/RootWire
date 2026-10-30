# Local overrides to implementer-brief.md and review-brief.md

Written 2026-10-30 when orchestration moved from the cloud container to the
owner's machine. Where these differ from the two briefs, these win.

- **Paths.** The clone is `/home/eonraider/programming/NETProtocols`. Agent
  worktrees live under `/home/eonraider/programming/wt/` (the orchestrator
  creates them and names the one you work in). Reviewers put scratch work in
  the scratchpad directory their prompt names, not `/tmp/claude-0/...`.
- **Tools.** `uvx` is not on PATH: use `uv tool run` wherever the briefs say
  `uvx`. `python3` is 3.10 here; run `scripts/check_fixtures.py` and
  benchmarks with `python3.12`.
- **Privileges and daemons.** No passwordless sudo, and none of the capture
  daemons are installed on the host. Captures run inside a privileged Docker
  container (`--cap-add NET_ADMIN`, daemons installed in the image), owner
  decision 2026-10-30. Docker 29.9.2 is available to the user account.
- **Kernel.** IPv6 is enabled here (the cloud kernel had `ipv6.disable=1`).
  Bridge, veth and MPLS routing are modules.
- **Commit trailer.** End every commit message with exactly
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and nothing else
  (drop the cloud `Claude-Session` line).
- **Mutation.** Lesson 5's checksum-only mutmut command can't pass the
  survivor gate. Either run the full filter set from
  `.github/workflows/mutation.yml`, or leave it to the orchestrator, who
  dispatches `mutation.yml` on the pushed branch.
- **Ladder** (local form):
  `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q -o addopts="" -p no:cacheprovider && python3.12 scripts/check_fixtures.py tests/fixtures && uv tool run bandit -q -r -t B324 src scripts tests`
