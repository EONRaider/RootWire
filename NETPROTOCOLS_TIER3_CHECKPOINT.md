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
| #186 LLDP | `claude/lldp` | — | ✅ merged as #253 (`5a6eb7a`) | — |
| #188 LLC/802.3 | `claude/llc` | — | ✅ merged as #254 (`aa4ac6a`) | — |
| #189 STP | `claude/stp` | `ffbd9fd` | `claude/llc` 5571ead merged in (ladder green, 5055 passed); Review: changes needed — blocking: GARP (Protocol ID 0x0001 at DSAP 0x42) raised in strict walks; should-fix: non-root BPDU accessor tests, PVST+/MST rationale, checker attributions, citations. Fixes pushed to origin claude/cdp (2a76676..082eb48, no PR yet, pending re-review: zero-tail rule, error-field tests, Wireshark table pins, docs; ladder 5172 passed, mutation gate exit 0). Re-review: blocking fix approved; round 2 (LLDP-rationale sentence, phantom-TLV fuzz branch, zeros-inside-802.3-Length docs, relative overrun error fields, memoryview scan) with the same fixer | re-review round 2 → merge origin/master (`aa4ac6a`) → PR |
| #190 CDP | `claude/cdp` | `082eb48` | `claude/llc` 5571ead merged in (ladder green, 5140 passed). Review: changes needed — blocking: a TLV Length < 4 inside the PDU silently stops the walk (verify() can pass); also CDPAddress.ip length pins, TLV-name table pin, rationale/Wireshark wording nits. Fixes pushed to origin claude/stp (086bb53..ffbd9fd, no PR yet: GARP gate in LLC (`_other_protocol_id`), non-root BPDU pins, tracemalloc test, rationale/citation fixes, checker bit 8 in RST; ladder 5107 passed). Re-review: GARP gate approved; round 2 (checker gated on UI/I Control, exactly-two-octet tests, PVST+ SSTP wording, nits) with the same fixer. At merge: rename master's mermaid LLDP node (id `L` collides with LLC) and fold LLC into ARCHITECTURE's 'BGP and MPLS are the two exceptions'; master's _base.py decode-context paragraph becomes three headers (BGP, MPLS, LLC) | merge origin/master after STP lands → PR → mutation.yml (touches checksum.py) |

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

## Working files

The shared agent briefs are saved next to this file in `netprotocols-tier3/`:
`implementer-brief.md` (hard rules, lessons from Tier 1/2 review, ladder, commit trailers)
and `review-brief.md` (the independent-review checklist). One correction to the implementer
brief: lesson 5's checksum-only mutmut command can't pass the survivor gate, so run CI's
full filter set from `.github/workflows/mutation.yml` instead.

`netprotocols-tier3/tagging-prompt.md` is the prompt for the owner's local session that
pushes the v2.4.0 and v2.5.0 tags. The owner asked to be handed it "when the time is right",
so hand it over at the next release point (with 2.6.0 added once Tier 3 ships), not now.

Current mode: **resumed 2026-10-28.** Tier 3 work continues (see the status table).
