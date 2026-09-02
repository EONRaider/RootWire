# Contributing

When contributing to this repository, please first discuss the change you wish to make via issue,
email, or any other method with the owners of this repository before making a change.

## Development setup

RootWire is developed with [uv](https://docs.astral.sh/uv/). Clone the
repository and sync the environment, which installs the project along with the
`dev` dependency group:

```
git clone https://github.com/EONRaider/RootWire.git
cd RootWire
uv sync
```

Live capture opens a raw socket and therefore needs root on Linux, but nothing
in the test suite does. The 65-frame corpus of real captured traffic is
replayed through the whole pipeline from disk, so the full suite runs
unprivileged on any operating system.

## Checks

Run these before opening a pull request. They are the same commands CI runs, so
a clean local run is a good predictor of a green pipeline:

```
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
```

`mypy` runs in strict mode over `src`. Tests run against Python 3.12, 3.13 and
3.14 in CI; locally, whichever interpreter `uv sync` resolved is enough for most
work.

If you change dependencies in `pyproject.toml`, run `uv lock` and commit the
updated `uv.lock` in the same change. CI installs from the lockfile, so an
unlocked dependency edit has no effect on the pipeline and will fail there while
appearing to work locally.

## Pull Request Process

1. Fork this Project
2. Create your Feature Branch (`git checkout -b featurebranch/Feature`)
3. Commit your Changes (`git commit -m 'Add some Feature'`)
4. Push to the Branch (`git push origin featurebranch/Feature`)
5. Open a Pull Request

Opening a pull request fills in
[the template](.github/pull_request_template.md) automatically. It asks what
changed and why, which checks you ran, and how you verified the behaviour —
delete whatever does not apply to your change.

Leave *Allow edits by maintainers* enabled on your pull request. It lets a
maintainer update your branch when the base branch moves under you, which
resolves conflicts and stale CI without any work on your part.

Beyond that:

- Cover new behaviour with tests, including its failure paths. Malformed and
  truncated input is diagnosed rather than fatal — see the decoding note below —
  so the interesting cases are usually the broken ones.
- Add a `CHANGELOG.md` entry under *Unreleased* for anything user-facing. The
  format is [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and the
  project follows [SemVer](https://semver.org/).
- Update `README.md` when you change the command-line interface or the output
  formats, and `ARCHITECTURE.md` when you change the shape of the pipeline
  itself — how frames are captured, decoded, or dispatched to outputs.

## A note on decoding

RootWire promises that malformed or truncated frames are diagnosed instead of
crashing the capture: unknown protocols end the decode chain gracefully, and a
16-layer cap keeps crafted extension-header stacks from amplifying. That promise
is the reason the parser is defensive everywhere it touches attacker-controlled
bytes.

If your change touches the decode path, treat that promise as part of the
contract you are keeping. Say in the pull request how it still holds for the
inputs you introduced.

## Code of Conduct

### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable
behavior and are expected to take appropriate and fair corrective action in
response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or
reject comments, commits, code, wiki edits, issues, and other contributions
that are not aligned to this Code of Conduct, or to ban temporarily or
permanently any contributor for other behaviors that they deem inappropriate.

### Scope

This Code of Conduct applies both within project spaces and in public spaces
when an individual is representing the project or its community. Examples of
representing a project or community include using an official project e-mail
address, posting via an official social media account, or acting as an appointed
representative at an online or offline event. Representation of a project may be
further defined and clarified by project maintainers.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org/version/2/0/code_of_conduct/) version 2.0.
