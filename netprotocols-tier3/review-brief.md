# Tier 3 independent review brief

You are an independent, adversarial reviewer of one protocol branch of
NETProtocols (zero-dependency, mypy-strict Python packet codec; GitHub
EONRaider/NETProtocols, public). You did not write this code. Your job is to
find real defects before it becomes a PR — not to approve it.

## Rules

- Read-only on the branch worktree you're given: do not edit, commit, merge,
  push, or make any GitHub write. Put all scratch work (scripts, modified
  copies, pcaps) under
  /tmp/claude-0/-home-user-RootWire/5e872283-09f8-5b0d-a0cd-9df99c14f8f0/scratchpad/review-<protocol>/.
  To run tests against a modified copy, copy the worktree (excluding .venv and
  mutants/) or use `git worktree add --detach` into your scratch dir from
  /home/user/netprotocols — then remove that worktree when done.
- Don't run network captures or start routing daemons unless you need to
  check a claim about the capture script; if you do, use namespace names
  starting with `nprv` + your protocol (e.g. `nprvbgp-a`) and clean up.
- Other agents are working in parallel in /home/user/wt/*; touch only your
  scratch dir.

## What to check (with evidence: file:line, a failing input, or a command)

1. Correctness against the RFCs: field layout, widths, offsets, flags, the
   names given to values; fetch the RFC text (curl https://www.rfc-editor.org/rfc/rfcNNNN.txt)
   rather than relying on memory.
2. The decode contract (src/netprotocols/_base.py, ARCHITECTURE.md): never
   raises anything but ProtocolError subclasses on any input; truncation and
   invalid-field errors carry correct field/offset; accessors never raise;
   `bytes(decode(x)) == x[:header_len]`; constructors validate what they
   claim to. Build hostile inputs (fuzz with Hypothesis or a quick random
   loop, lying lengths, counts that overflow, zero-length TLVs, trailing
   padding/FCS bytes) and try to break it.
3. Dispatch: registry entries, family-specific tables (ip.proto vs
   ip.proto.v6), port guesses; what happens to traffic that isn't this
   protocol but arrives on its number/port.
4. Checksums (if any): computed independently by you (not via checksum.py)
   on real frames from the fixture and on constructed edge cases; both the
   library and scripts/check_fixtures.py must agree with the RFC, and a
   tampered frame must fail the checker.
5. The fixture: is it really the capture script's output (re-run the
   script only if needed), does MANIFEST describe it truthfully, does the
   script's cleanup kill only its own processes/namespaces, does it assert
   the composition, is anything masked with `|| true` that matters.
6. Tests: do they test what their names/docstrings claim (a test that checks
   vocabulary rather than behaviour is a defect)? Mutate the code in your
   scratch copy (flip a comparison, drop a branch, swap two fields) and see
   whether the suite notices; report mutations that survive.
7. Docs/CHANGELOG/MANIFEST/ARCHITECTURE/README: every claim true and
   precise; no claim broader than the tests support; counts consistent.
8. Code quality: idiomatic, matches the surrounding code; complexity
   (`uvx radon cc -s -n C <files>`), docstring style
   (`uv run ruff check --select D --config 'lint.pydocstyle.convention="pep257"' <new files>`).
9. Run the ladder yourself in the worktree (read-only commands):
   `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q -o addopts="" && python3 scripts/check_fixtures.py tests/fixtures`
   and report real exit codes.

## Report (your final message)

Verdict: approve / changes needed. Then each finding as:
**[severity: blocking | should-fix | nit] title** — file:line, what is
wrong, the evidence (failing input, command + output, RFC quote), and the
fix you'd suggest. Separate "verified correct" items briefly, and list what
you could not verify.
