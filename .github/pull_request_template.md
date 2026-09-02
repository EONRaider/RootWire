<!--
  Thanks for contributing to RootWire.

  Keep this short. A couple of dense paragraphs that explain what changed
  and why beats a long form with every box ticked. Delete any section that
  does not apply.
-->

## Summary

<!--
  What this changes, and why it is worth changing. If the diff is not
  obvious on its own, say what the behaviour was before and what it is
  after. For a bug fix, describe how it failed.
-->

## Related issues

<!-- e.g. Closes #12 — or "None" for standalone work. -->

## Verification

<!--
  How you know this works. Name the checks you ran locally and anything
  you exercised by hand (a capture against a live interface, a replayed
  pcap, a crafted frame). "CI is green" alone is not verification for a
  behaviour change.
-->

- [ ] `uv run ruff check` and `uv run ruff format --check`
- [ ] `uv run mypy` (strict)
- [ ] `uv run pytest`

## Checklist

- [ ] Tests cover the new behaviour, including its failure paths.
- [ ] Dependency changes are locked — ran `uv lock` and committed `uv.lock`
      alongside the `pyproject.toml` edit.
- [ ] User-facing changes have a `CHANGELOG.md` entry under *Unreleased*.
- [ ] Docs updated if this changes the CLI, the output formats, or the
      decode pipeline (`README.md`, `ARCHITECTURE.md`).

<!--
  On decoding: RootWire promises that malformed or truncated frames are
  diagnosed rather than crashing the capture. If you touched the decode
  path, say how that promise still holds for the inputs you added.
-->
