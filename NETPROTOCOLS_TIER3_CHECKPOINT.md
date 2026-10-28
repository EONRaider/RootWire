# NETProtocols — Tier 3 checkpoint (for resuming later)

Repository: EONRaider/NETProtocols. Roadmap #170; Tier 3 epic #173 (target 2.6.0).
Written 2026-10-25 by the orchestrating Claude Code session. Every branch below
is pushed to `origin` (verified with `git ls-remote`), so this state survives the
container being reclaimed. Branches of already-merged PRs (`claude/vrrp`, `rip`,
`ospf`, `pim`, `bgp`, `mpls`, `release-2.5.0`, `llc`) were deleted on GitHub after merge.
All of their commits are in `origin/master`.

## Standing instructions from the owner

- Merge PRs on green CI with `merge_method: "merge"`. Never squash.
- Ignore CodeRabbit.
- One PR per issue, each merged before the next PR opens.
- Steward rule (`.claude/skills/steward/SKILL.md`): a fix for a CI, bot or
  reviewer finding is implemented by an agent independent of the code's
  author, then reviewed by another independent agent, before it is pushed.
- Sub-agents make no GitHub writes. The session cannot push tags; the owner does.
- Mode: the owner resumed work on 2026-10-28 (the earlier "hold" is lifted); see the
  last line of this file for where things stand.

## Release state

| Version | Merge commit | Tag |
|---|---|---|
| 2.4.0 | `0a33a5d` | not pushed yet (owner) |
| 2.5.0 | `7549dc0` | not pushed yet (owner) |
| 2.6.0 | `0566f88` | not pushed yet (owner) |

Push `v2.4.0`, then `v2.5.0`, then `v2.6.0`, each after the previous Release run finishes
(`netprotocols-tier3/tagging-prompt.md`, handed to the owner 2026-10-28).

## Tier 3 status

| Issue | Branch (on origin) | Head | State | Next step |
|---|---|---|---|---|
| #187 MPLS | `claude/mpls` | — | ✅ merged as #252 (`ca73b1a`) | — |
| #186 LLDP | `claude/lldp` | — | ✅ merged as #253 (`5a6eb7a`) | — |
| #188 LLC/802.3 | `claude/llc` | — | ✅ merged as #254 (`aa4ac6a`) | — |
| #189 STP | `claude/stp` | — | ✅ merged as #255 (`fd803a6`; CI fix b416e3f: bare cisco.com link 403 in lychee, pickle test flagged by Bandit/CodeFactor) | — |
| #190 CDP | `claude/cdp` | — | ✅ merged as #256 (`c008e18`; mutation.yml green on dfe1272) | — |

`claude/stp` and `claude/cdp` are built on `claude/llc` and already include its final
commits (`5571ead`), so merging `origin/master` into them should conflict only where
they edit text that the MPLS/LLDP merge also touched (CHANGELOG, CLAIMS, MANIFEST counts).

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

1. ~~The `ethertype` table refuses keys outside 0x0600–0xFFFF.~~ Reversed by the owner:
   `ethertype` accepts any key again, because GRE and SNAP still consult it and RFC 1701
   assigns GRE types below 0x0600. Only the new `llc.dsap`/`llc.snap` tables have key
   ranges. Ethernet and VLAN still dispatch type/length ≤ 1500 to LLC (inherent to #188).
2. README "Why" decode claim (2.5.0): dpkt is 1.3× faster on the 265-frame corpus.
   The cause is the workload, not a regression. Follow-up: #250.
3. **GARP at DSAP 0x42 (#189), owner decision 2026-10-28:** LLC sniffs the two octets after
   the Control for DSAP 0x42 (compare=False decode-context field, the BGP/MPLS convention) and
   dispatches to `llc.dsap` only when they are 0x0000; GARP frames end the walk at LLC. STP.decode
   still rejects Protocol ID != 0 on a direct decode.
4. Benchmark baseline re-recorded at 2.5.0 on 265 frames (normalized 5.4344).
   Gate-noise follow-up: #251.

## Follow-up issues filed during this roadmap

#235, #236, #237, #238, #239, #241 (docstring standard, deferred), #242, #244,
#250, #251. #197 closes the roadmap.
#257 (filed at 2.6.0): sctp.py's zero-tail scan copies the tail for `bytes` input.

## Working files

The shared agent briefs are saved next to this file in `netprotocols-tier3/`:
`implementer-brief.md` (hard rules, lessons from Tier 1/2 review, ladder, commit trailers)
and `review-brief.md` (the independent-review checklist). One correction to the implementer
brief: lesson 5's checksum-only mutmut command can't pass the survivor gate, so run CI's
full filter set from `.github/workflows/mutation.yml` instead.

`netprotocols-tier3/tagging-prompt.md` is the prompt for the owner's local session that
pushes v2.4.0, v2.5.0 and v2.6.0, in that order. It was handed to the owner on 2026-10-28,
after 2.6.0 merged.

Current mode: **Tier 3 complete and 2.6.0 merged (2026-10-28).** #173 is all ✅ and left open for the owner to close. Waiting on the owner to push v2.4.0, v2.5.0, v2.6.0. Open follow-ups: #235–#239, #241, #242, #244, #250, #251, #257; #197 closes the roadmap.

## 2.6.0 release (done, 2026-10-28)

- Follow-up filed: #257 (SCTP zero-tail scan copies the tail for `bytes` input).
- ✅ **2.6.0 merged as #258 (`0566f88`)**: PR CI, fuzz.yml (fuzz + atheris) and mutation.yml all green on
  9230cd2. CodeRabbit's two comments ignored per the owner's rule. Tagging prompt updated with v2.6.0
  and handed to the owner. Roadmap work for Tier 3 is complete; nothing further is in flight.
