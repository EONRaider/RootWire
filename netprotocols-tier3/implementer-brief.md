# Tier 3 implementer brief (shared by every Tier 3 agent)

You implement ONE protocol for NETProtocols, a zero-dependency, mypy-strict
Python packet codec. The repo clone is /home/user/netprotocols (GitHub:
EONRaider/NETProtocols, public). Your issue text is in your prompt; the parent
roadmap is #173 (Tier 3, L2 discovery & tunneling) under #170. Master is at
7549dc0 (2.5.0: Tier 1 and Tier 2 shipped).

## Hard rules

- Work ONLY in your own worktree (created as your first step, see your prompt).
  Never touch /home/user/netprotocols's own checkout or another agent's
  worktree under /home/user/wt/.
- NO GitHub writes of any kind: no push, no PR, no issue/PR comments. Commit
  locally on your branch only. Reading the public repo/issues is fine.
- Other agents are capturing traffic in parallel on this machine. Every netns,
  veth, bridge and tunnel name you create MUST start with your prefix (given in
  your prompt), and your cleanup trap must delete only those. Never kill
  processes you didn't start (no `pkill bird`/`pkill zebra` — kill by PID or by
  your netns: `ip netns pids <ns> | xargs -r kill`).
- Packages already installed: lldpd 1.0.18 (can speak LLDP, and CDP with
  `-c`; NOT running — start your own instance inside your own netns with its
  own `-u` control socket path and `-I` interface list, and kill it by PID),
  bird2, frr, keepalived, tcpdump, ethtool, iproute2 (`ip`, `bridge`). If you
  need another package, apt-get install it but expect the dpkg lock may be
  briefly held by another agent; retry. mstpd (RSTP) is not available.
- Kernel facts: CONFIG_BRIDGE=y, CONFIG_STP=y, CONFIG_LLC=y (a Linux bridge
  with `stp_state 1` emits real 802.1D BPDUs); CONFIG_MPLS=y but
  CONFIG_MPLS_ROUTING is NOT set (the kernel cannot forward or encapsulate
  MPLS; there is no /proc/sys/net/mpls). The kernel boots with
  ipv6.disable=1: no IPv6 traffic can be captured. Where the kernel or a
  daemon cannot produce a frame, build it in a stdlib-only script and send it
  through a raw socket over a veth pair (the precedent is
  scripts/ipsec_fixture_packets.py + scripts/capture_fixtures_ipsec.sh), and
  say plainly in MANIFEST which bytes the script built.
- Real exit codes only. Never pipe a check through grep/tail in a way that hides
  its exit status when deciding pass/fail.

## Read first

- ARCHITECTURE.md — especially the add-a-protocol cookbook, the decode contract
  and its "rules", the dispatch tables, and the paragraphs on protocols without
  a length field (SCTP) and on port-dispatch guessing (VXLAN/DNS/DHCP).
- src/netprotocols/_base.py (decode contract), registry.py, _defaults.py,
  _enums.py, walk.py, checksum.py, flow.py.
- CONTRIBUTING.md and .github/pull_request_template.md (the checklist your work
  must satisfy).
- The Tier 1/2 precedents, which went through several rounds of independent
  review — copy their shape: layer2/vlan.py (a thin L2 layer chaining onward
  through `ethertype`), layer7/vxlan.py, layer3/vrrp.py, layer7/rip.py,
  layer3/ospf.py, layer3/pim.py (TLV options through `_tlv`), layer7/bgp.py,
  and their tests and capture scripts (scripts/capture_fixtures_vrrp.sh,
  _rip.sh, _ospf.sh, _pim.sh, _bgp.sh, _vxlan.sh, _ipsec.sh).
- `git log --oneline -60` and the Tier 2 PRs (#243, #245-#248) to see what
  reviewers caught.

## Lessons from Tier 1 review (each of these was a real finding — don't repeat)

1. The walker hands each decoder `data[cursor:]`; nothing trims to the IP or
   UDP length (#235), so Ethernet zero padding and FCS bytes can reach you.
   Bound your header by its own length fields where it has them; if it has
   none, say explicitly in the module docstring how trailing bytes are handled,
   and test frames with appended zero padding AND a 4-byte nonzero trailer.
2. Decode never raises anything but ProtocolError subclasses, on any input
   (fuzz-tested). Accessors never raise (fuzz property). Round trip:
   `bytes(X.decode(x)) == x[:X.decode(x).header_len]` (the repo's contract —
   check ARCHITECTURE for the exact wording, including any decode context).
3. Don't write docs/comments/commit messages that claim more than you tested.
   A reviewer caught "every other constructor accepts at most what its decode
   does" — false. If you claim a property, have a test that checks it.
4. CodeFactor fails the PR on a complex method. Keep functions small: new
   checksum arms go in their own helper (like `checksum._gre_checksum` /
   `_sctp_checksum`) so `compute()`/`verify()` don't grow; new checker cases go
   into `scripts/check_fixtures.py`'s `_check_transport_v4`/`_v6` (or a new
   helper), not into the dispatchers. Check with
   `uvx radon cc -s -n C src scripts` (nothing new at grade C or worse).
5. Mutation gate: `checksum.py`, `_tlv.py` (and parts of dns.py/http.py) are in
   mutmut scope (pyproject.toml [tool.mutmut], .github/workflows/mutation.yml).
   If you touch any in-scope file, run, in YOUR worktree:
   `rm -f mutants/mutmut-stats.json; uv run mutmut run 'netprotocols.checksum.*'`
   (and/or `'netprotocols._tlv.*'`), then `uv run mutmut results --all true >
   r.txt; uv run python scripts/check_mutmut_survivors.py r.txt` — it must exit
   0. Kill survivors with tests; never add allowlist entries for killable
   mutants (an equivalent mutant may be allowlisted with a reason — say so in
   your report).
6. `scripts/check_fixtures.py` is the corpus's independent oracle: stdlib only,
   shares no code with the library. Extend it so every new fixture's checksums
   (if the protocol has any) are verified independently, and so a tampered
   frame fails. Every committed fixture must pass it.
7. Capture scripts: two (or more) netns over a veth pair, offloads off,
   tcpdump on one side writing to tests/fixtures/staging/, a cleanup trap that
   kills tcpdump by PID and deletes only your namespaces, no `|| true` masking
   of the traffic that matters, and an exact assertion of the captured frames'
   composition at the end (count and types). Then copy into tests/fixtures/.
   Run the script for real — the fixture must be the script's own output.
   Document in tests/fixtures/MANIFEST.md which bytes the daemon/kernel built.
8. Corpus counts are enforced by tests/test_docs.py: MANIFEST "N frames across M
   scenarios", README's "N-frame corpus … across M scenarios", ARCHITECTURE.
   Update those. README's "Why NETProtocols" sentence currently reads
   "Measured against `dpkt 1.9.8` and `scapy 2.8.0` on the 265-frame corpus
   of real captured traffic" — that names the corpus the figures were
   MEASURED on, and test_docs' regex `(\d+)-frame corpus` would match it
   first. Reword exactly that phrase to "on the 265 frames of real captured
   traffic the corpus held at 2.5.0" (leave the rest of the sentence and the
   bullets alone), so the regex reaches the coverage sentence further down,
   which is the one you update. Also update the MANIFEST "N scenarios ...
   captured separately" count and list if your fixture comes from its own
   capture script. Adding frames moves the CI benchmark gate's normalized
   figure (benchmarks/baseline.json); do NOT re-record the baseline — report
   the local `scripts/benchmark.py --check --threshold 15` reading instead. Do NOT update docs/CLAIMS.md §5.1/§5.2/§5.3 or the coverage
   comment in pyproject.toml — the orchestrator re-derives those at
   integration (other branches change them too). If a test forces you to touch
   one, make the minimal change and flag it in your report.
9. Register in the fuzz/property suites: tests/test_fuzz.py ALL_PROTOCOLS and
   ROUND_TRIP_STRATEGIES, an accessor-safety property if you add accessors, the
   contract/truncation test, the corpus checksum cases (tests/test_checksum.py)
   if the protocol has a checksum, and the corpus coverage set
   (tests/test_corpus.py). Enum members carry display names in lockstep.
10. Docs: README coverage table + its coverage wording if affected (not the
    "Why" figures, which are re-measured at release),
    ARCHITECTURE chain diagram + layout map, CONTRIBUTING layout list,
    MANIFEST row + note, CHANGELOG under `## [Unreleased]` (`### Added` for the
    protocol, `### Development` for the fixture/tooling). Keep entries factual.
11. Docstrings: new code follows the repo's de facto standard, which #241 will
    formalize — reST field lists (`:param x:`, `:raises X:`), types only in
    annotations, cross-references with `:class:`/`:attr:`/`:func:`, PEP 257
    layout (one-line summary, blank line, body), imperative-mood summaries,
    RFC section citations like the existing modules. Before committing, run
    `uv run ruff check --select D --config 'lint.pydocstyle.convention="pep257"'`
    on YOUR new files only and fix what it reports there (don't sweep others).

## Lessons from Tier 2 review (each was a real finding)

12. Decode can be handed a `memoryview` (tests/test_contract.py's
    TestDecodeInputs); anything you do to a body (`.rstrip`, `.find`,
    slicing then comparing to bytes) must work on one, and the instance must
    not retain it. Test decode on `memoryview(raw)`.
13. No quadratic work in decode: a per-element scan of the remaining buffer
    (e.g. re-checking "is the rest all zeros" at every TLV) turned a 64 KiB
    body into seconds. Compute such facts once. Add a test that a large
    hostile body decodes in bounded work (precedent: tests/test_pim.py's
    TestHelloCost counts bytes read).
14. Names for code points come from the authoritative registry, fetched
    (IANA, IEEE), not memory; say in a comment where and when you fetched
    them. Every value a table names must match the source exactly.
15. CI security scanners: CodeFactor runs Bandit (B324: `hashlib.md5`/`sha1`
    need `usedforsecurity=False`); CodeQL flags a dict key or label containing
    "password"/"secret" that flows into print. Run
    `uvx bandit -q -r -t B324 src scripts tests` before your final commit.
16. Complexity: keep `scripts/check_fixtures.py`'s dispatchers
    (`_check_l3`, `_check_upper_v4/_v6`, `_check_transport_v4/_v6`) from
    growing — add a helper instead (precedent: `_check_routing_v4`). Run
    `uvx radon cc -s -n C src scripts` and compare against master's output:
    nothing new at C or worse.
17. If you change a registry default that docs, examples or tests use as a
    stand-in (they register fakes at a "free" number), move those to a number
    that stays free (precedent: SCTP moved registry examples from 132 to 253,
    RFC 3692's experimental range) and keep the examples runnable.

## Ladder (all must exit 0 before your final commit)

    uv run ruff check . && uv run ruff format --check . && uv run mypy \
      && uv run pytest -q -o addopts="" && python3 scripts/check_fixtures.py tests/fixtures \
      && uvx bandit -q -r -t B324 src scripts tests

Coverage: the repo enforces a coverage threshold (see pyproject.toml); your new
module should be at 100% line+branch.

Commit a staging copy of every new fixture under tests/fixtures/staging/ as
the existing ones are (the repo tracks one per fixture).

## Commits

Conventional Commits subject (e.g. `feat(layer3): decode VRRP ...`), a body
explaining what and why, and end every commit message with exactly:

    Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
    Claude-Session: https://claude.ai/code/session_01CEQCZGyuvpMyZwUbDucF3G

Several focused commits are fine. Never amend or rewrite a commit you didn't
make; never force anything.

## Final report (your last message)

1. Branch name and final commit SHA; `git log --oneline origin/master..HEAD`.
2. What you built: classes, dispatch registrations, accessors, fixture (file,
   frame count, what's in it, how it was captured), checker changes.
3. Design decisions a reviewer should look at, and anything you deliberately
   scoped out (with the issue's permission or flagged as a deviation).
4. The exact ladder commands and their real exit codes; mutmut results if run;
   radon results for touched files.
5. Anything you could not do or verify, and any CLAIMS/pyproject edits you were
   forced into.
