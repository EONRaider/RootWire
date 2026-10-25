# NETProtocols — Tier 3 checkpoint (for resuming later)

Repository: EONRaider/NETProtocols. Roadmap #170; Tier 3 epic #173 (target 2.6.0).
Written 2026-10-25 by the orchestrating Claude Code session. Every branch below
is pushed to `origin` (verified with `git ls-remote`), so this state survives the
container being reclaimed. Branches of already-merged PRs (`claude/vrrp`, `rip`,
`ospf`, `pim`, `bgp`, `mpls`, `release-2.5.0`) were deleted on GitHub after merge.
All of their commits are in `origin/master`.

## Standing instructions from the owner

- Merge PRs on green CI with `merge_method: "merge"`. Never squash.
- Ignore CodeRabbit.
- One PR per issue, each merged before the next PR opens.
- Steward rule (`.claude/skills/steward/SKILL.md`): a fix for a CI, bot or
  reviewer finding is implemented by an agent independent of the code's
  author, then reviewed by another independent agent, before it is pushed.
- Sub-agents make no GitHub writes. The session cannot push tags; the owner does.
- Current mode: **hold**. Integrate only what is ready or needs small fixes; the rest
  stays on hold until the owner says otherwise.

## Release state

| Version | Merge commit | Tag |
|---|---|---|
| 2.4.0 | `0a33a5d` | not pushed yet (owner) |
| 2.5.0 | `7549dc0` | not pushed yet (owner) |

Push `v2.4.0` before `v2.5.0`.

## Tier 3 status

| Issue | Branch (on origin) | Head | State | Next step |
|---|---|---|---|---|
| #187 MPLS | `claude/mpls` | — | ✅ merged as #252 (`ca73b1a`) | — |
| #186 LLDP | `claude/lldp` | `adc9573` | PR #253 open (master merged in; CLAIMS re-derived) | merge on green |
| #188 LLC/802.3 | `claude/llc` | `0d29253` | code and tests approved; doc-fix commit `0d29253` (three CHANGELOG/MANIFEST sentences plus nits) awaiting its independent re-review | independent re-review of the doc fix → merge master → re-derive CLAIMS → PR → merge |
| #189 STP | `claude/stp` | `fcea600` | **on hold**: implemented, ladder green, NOT reviewed | independent review → fixes → merge master (after #188) → PR |
| #190 CDP | `claude/cdp` | `a13e7ad` | **on hold**: implemented, ladder green, mutation gate passed, NOT reviewed | independent review → fixes → merge master (after #188) → PR → mutation.yml (touches checksum.py) |

`claude/stp` and `claude/cdp` are built on `claude/llc` at `8dfe2c4`. They contain
#188's commits and must not be merged before #188.

## Known integration notes for the held branches

- STP and CDP both edit the same #188 CHANGELOG sentence, ARCHITECTURE's
  "first decoder behind that bound" line, and the `WholeBuffer` docstring in
  `tests/test_llc.py`, so expect conflicts between them.
- STP corrected two #188 CHANGELOG sentences that a built-in DSAP 0x42 makes false.
  Re-check them against #188's final wording.
- CDP's checksum uses lldpd's odd-byte rule: a final byte v ≥ 0x80 sums as
  `0xFF00 + v - 1`. #188's review verified it against lldpd's compiled
  `frame_checksum`.
- The mutation gate (`scripts/check_mutmut_survivors.py`) fails unless every
  `only_mutate` file is mutated. Run CI's full filter set from
  `.github/workflows/mutation.yml`, not a checksum-only subset.

## Decisions taken that the owner may want to revisit

1. The `ethertype` table refuses keys outside 0x0600–0xFFFF (`InvalidRegistryKeyError`,
   #188). On 2.5.0, registering a low key was the only way to decode STP. The refusal
   is declared as a behaviour change in CHANGELOG.
2. README "Why" decode claim (2.5.0): dpkt is 1.3× faster on the 265-frame corpus.
   The cause is the workload, not a regression. Follow-up: #250.
3. Benchmark baseline re-recorded at 2.5.0 on 265 frames (normalized 5.4344).
   Gate-noise follow-up: #251.

## Follow-up issues filed during this roadmap

#235, #236, #237, #238, #239, #241 (docstring standard, deferred), #242, #244,
#250, #251. #197 closes the roadmap.

## Working files (ephemeral; regenerable)

The shared agent briefs were in the session scratchpad (`tier3-brief.md`,
`tier3-review-brief.md`). They are not needed to resume. The process is above,
and the repo's CONTRIBUTING/ARCHITECTURE/steward skill hold the rules.
