Tag and publish two NETProtocols releases, in this order: 2.4.0, then 2.5.0.

Work in my local clone of EONRaider/NETProtocols (GitHub may redirect from
EONRaider/netprotocols). Pushing a `v*` tag triggers `.github/workflows/release.yml`.
That workflow runs the full CI ladder on the tagged commit. It then publishes to
PyPI through the `pypi` environment, using a trusted publisher. Last, it creates a
GitHub release from that version's CHANGELOG section and marks it `--latest`.
A PyPI version can be yanked but never replaced, so check everything before each push.

Release commits on `master` (both are GitHub merge commits):
- v2.4.0 → `0a33a5d` ("Merge pull request #240 from EONRaider/claude/release-2.4.0")
- v2.5.0 → `7549dc0` ("Merge pull request #249 from EONRaider/claude/release-2.5.0")

Steps:

1. `git fetch origin --tags`. Confirm both commits are ancestors of `origin/master`
   (`git merge-base --is-ancestor <sha> origin/master`). Confirm that
   `git ls-remote --tags origin 'v2.4.0' 'v2.5.0'` prints nothing. If either tag
   already exists, stop and tell me.
2. For each commit, check that the packaged version matches:
   - `git show <sha>:pyproject.toml | grep '^version'` → `2.4.0` / `2.5.0`;
   - `git show <sha>:src/netprotocols/__init__.py | grep __version__` → the same;
   - `git show <sha>:CHANGELOG.md | grep -n '^## \[<version>\]'` → exactly one heading.
3. Match the existing tags' style. v2.3.0 and v2.2.1 are lightweight tags; check with
   `git cat-file -t v2.3.0`, which prints `commit`. If I have tag signing configured
   and would rather sign, ask me before making an annotated or signed tag instead.
4. Tag and push v2.4.0 only:
   `git tag v2.4.0 0a33a5d && git push origin v2.4.0`.
5. Watch that tag's Release run until every job has finished:
   `gh run list --workflow release.yml --limit 3`, then `gh run watch <id>`.
   - If the `pypi` environment waits for approval, tell me and wait.
   - Afterwards, confirm https://pypi.org/project/netprotocols/2.4.0/ exists and
     that `gh release view v2.4.0` shows the release.
   - If any job fails, stop. Don't delete or move the tag, and don't push v2.5.0.
     Report the failing job and its log.
6. Only after 2.4.0's run has fully completed, tag and push v2.5.0:
   `git tag v2.5.0 7549dc0 && git push origin v2.5.0`.
   Watch that run as in step 5.
   - The order matters: each run creates its GitHub release with `--latest`. If the
     runs overlapped, 2.4.0 could end up marked latest.
   - Afterwards, confirm `gh release list` shows 2.5.0 as Latest, and that
     https://pypi.org/project/netprotocols/ shows 2.5.0.
7. Report both tags' SHAs, the two Release run URLs, and the PyPI and GitHub
   release links.

Never force-push a tag, delete a remote tag, or retag a commit without asking me first.
