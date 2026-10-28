You're taking over orchestration of the NETProtocols post-2.2.1 roadmap (#170) from a cloud
Claude Code session, and continuing it from my local machine. Read this whole prompt before
acting. When you've read it and checked the state below, tell me what you found and ask me
what to start with. Don't start new feature work until I answer.

## Repository and state (as of 2026-10-28)

- **Repo:** EONRaider/NETProtocols (GitHub redirects from EONRaider/netprotocols). It is a
  Python packet codec, positioned against dpkt and scapy. Use my local clone, and run
  `git fetch origin --tags` first.
- **master:** `0566f88` (Merge #258, "chore(release): 2.6.0"). Released and tagged:
  - v2.4.0 at `0a33a5d`, Tier 1: SCTP, IPIP, ESP, AH, VXLAN;
  - v2.5.0 at `7549dc0`, Tier 2: VRRP, RIP, OSPF, PIM, BGP;
  - v2.6.0 at `0566f88`, Tier 3: MPLS, LLDP, IEEE 802.3 LLC/SNAP framing, STP, CDP.

  All three are on PyPI and as GitHub releases, and v2.6.0 is Latest. The tier epics
  #171, #172 and #173 are closed. #170's table shows tiers 1–3 shipped.
- **Remaining roadmap:**
  - Tier 4 (#174, target 2.7.0): NTP #191, TFTP #192, RADIUS #193, STUN #194 and
    HSRP #195. Sequencing is in #174.
  - Tier 5 (#175, target 2.8.0, stretch): TLS record layer and SNI, #196.
  - #197 closes the roadmap. Its progress comment from 2026-10-28 shows two of its
    criteria already met.
- **Open follow-ups:**
  - #235: honour IP/UDP lengths as walk bounds.
  - #236: IPv6 Routing header final destination in checksums and `flow_key`. Labelled bug.
  - #237: run `check_fixtures.py` in CI.
  - #238: SCTP chunk accessors and PPID dispatch.
  - #239: the mutmut cache.
  - #241: docstring standard, deferred.
  - #242: VRRPv3 RFC 9568 checksum.
  - #244: BGP vs `max_depth`.
  - #250: the decode gap to dpkt. It has 2.6.0 data and needs profiling.
  - #251: benchmark gate noise. It has CI data, so measure it on `ubuntu-latest`.
  - #257: SCTP's zero-tail scan copies the tail. Use `memoryview`, as CDP does.
- **Previous session's notes:** the durable checkpoint and agent briefs are on GitHub in
  **EONRaider/RootWire**, branch `claude/http-missing-protocols-metx8h`:
  - `NETPROTOCOLS_TIER3_CHECKPOINT.md`;
  - `netprotocols-tier3/implementer-brief.md` (hard rules, Tier 1–3 review lessons,
    ladder);
  - `netprotocols-tier3/review-brief.md` (the independent-review checklist).

  Read the two briefs before dispatching any agent, and keep that checkpoint, or a new
  one, updated and pushed after every state change.

## My standing rules (still in force)

1. Merge PRs on green CI, with `merge_method: merge` and the expected head SHA. Never
   squash or rebase-merge. Run unattended as much as you can.
2. Ignore CodeRabbit entirely (its comments, reviews and "changes requested"). Other
   checks, including CodeFactor and lychee, are real CI.
3. One PR per issue, each merged before the next PR opens. Each PR references its issue
   (`Closes #N`), updates `CHANGELOG.md` under `## [Unreleased]`, and follows
   `.github/pull_request_template.md`.
4. **Steward rule** (`.claude/skills/steward/SKILL.md` in the repo): an agent independent
   of the code's author implements every fix for a CI, bot or reviewer finding, and
   another independent agent reviews that fix before it is pushed to a PR. Small doc
   nits may be reviewed by you, the orchestrator, if you didn't write them.
5. Sub-agents make no GitHub writes. They commit locally in their own worktree, and you
   push. You may push to `claude/*` branches that have no PR yet, to keep state safe.
6. Never force-push, rewrite pushed history, skip or disable a test, or allowlist a
   killable mutant. Revert rather than rewrite.
7. **Tags and PyPI releases are mine.** You never push tags. At a release point, hand me
   a tagging prompt with the steps: verify, tag, push one tag, wait for its Release run
   to finish, then push the next, oldest first.
8. When a design decision is genuinely mine, ask with options and a recommendation.
   Earlier decisions of mine include: `ethertype` accepts any key, for RFC 1701 GRE
   types; and LLC sniffs the Protocol ID at DSAP 0x42, so GARP frames end at LLC.

## Per-protocol workflow that worked (Tiers 1–3)

1. **Implement:** an implementer agent works in its own `git worktree`, on branch
   `claude/<proto>` from `origin/master`, with the implementer brief. Its deliverables:
   - a decoder that meets the decode contract: `bytes(decode(x)) == x[:header_len]`,
     decode raises only `ProtocolError`, accessors never raise, a lying length raises;
   - a real captured fixture where possible (`scripts/capture_fixtures_<proto>.sh` with
     netns and veth, checked by `scripts/check_fixtures.py`), plus a MANIFEST entry;
   - tests, and fuzz and contract registration;
   - docs: README coverage row, ARCHITECTURE, CHANGELOG.
2. **Review:** an independent review against `review-brief.md`, then a fix from an
   independent fixer, then a re-review, repeated until approved.
3. **Integrate yourself:**
   1. Merge `origin/master` into the branch with a merge commit, resolving conflicts by
      keeping both sides. Most conflicts are both sides adding to the same lists.
   2. Grep for cross-references that went stale ("not decoded yet", counts, "the one
      built-in entry").
   3. Re-derive the corpus totals: README's "N-frame corpus … M scenarios", the MANIFEST
      count, and `docs/CLAIMS.md` §5.1–5.3.
   4. Re-derive the pyproject coverage comment. Count the protocol and strategy numbers
      by importing `tests/strategies.py` and `tests/test_fuzz.py`, not by arithmetic.
4. **Ladder,** which must exit 0 before any push:
   `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q -o addopts="" -p no:cacheprovider && python3 scripts/check_fixtures.py tests/fixtures && uvx bandit -q -r -t B324 src scripts tests`
   - Run `uv run pytest --cov=netprotocols --cov-report=term` for the CI coverage form.
   - Run `git diff --name-only origin/master -- '*.py' | xargs uvx bandit -q -s B101`,
     because CodeFactor flags Bandit findings such as `pickle`.
5. **Mutation gate:** if the PR touches a file in pyproject's `only_mutate` (`checksum.py`,
   `_tlv.py`, the DNS label helpers, `http.py`), dispatch `.github/workflows/mutation.yml`
   on the branch and wait for it before merging. Run it locally only with that workflow's
   full filter set.
6. **Open the PR,** watch it, and merge on green.

## Pitfalls already hit (don't repeat them)

- **lychee** checks the links in README, ARCHITECTURE, CONTRIBUTING, CHANGELOG and
  `docs/CLAIMS.md`. cisco.com returns 403 to CI, so cite such pages by title or number in
  those files and keep the URL in `.py` docstrings.
- **Briefs and agent reports can be wrong,** mine included. Verify file contents, counts
  and "already there" claims before relying on them.
- **The benchmark baseline** (`benchmarks/baseline.json`, 5.4344 from 2.5.0 on 265 frames)
  must not be re-recorded from a developer or cloud machine. Those read 9–19% below CI's
  `ubuntu-latest`, which would loosen the gate. See #251.
- **A release** re-measures every comparative README number per `docs/CLAIMS.md` Rule 4,
  modelled on the 2.5.0 (#249) and 2.6.0 (#258) release PRs: decode, encode, import,
  wheel and depth against dpkt 1.9.8 and scapy 2.8.0, with CPython 3.12, and saying
  plainly when a claim no longer holds. Dispatch `fuzz.yml` and `mutation.yml` on the
  release branch before merging it.
- **Commit trailers:** use your own harness's attribution. Don't copy the previous cloud
  session's `Claude-Session` link.

## First steps

1. Fetch, and confirm master is `0566f88` or later and the v2.4.0–v2.6.0 tags are as
   stated above. Check `gh issue list --state open` against the follow-up list, and
   whether anything has merged since.
2. Read the RootWire checkpoint and the two briefs.
3. Check the local toolchain: uv; Python 3.12 for benchmarks; `gh` authenticated;
   root/netns, tcpdump and the daemons a capture needs (Tier 4 will want ntpd/chrony,
   a TFTP server, FreeRADIUS, a STUN server and keepalived or similar for HSRP).
   Report what's missing.
4. Ask me whether to start Tier 4 (#174) or clear follow-ups first. #236 is a bug and
   #257 is small.
