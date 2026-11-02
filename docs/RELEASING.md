# Releasing briqyard

Use Conventional Commit subjects (`feat:`, `fix:`, `perf:`, `docs:`) for changes and
squash PR titles. Mark incompatible changes with `!` or a `BREAKING CHANGE:` footer.
[git-cliff](https://git-cliff.org/) generates grouped changelog entries and proposes
versions. Before 1.0, features and fixes increment the patch; incompatible changes
increment the minor. Release preparation commits use `chore(release):` and are excluded.

Install git-cliff 2.14.2 and use Python 3.11 or newer. Start from up-to-date main,
fetch tags, and create a release task branch. On that clean branch run:

```sh
python3 hack/release.py prepare
```

The command proposes the next version from commits since the latest reachable release
tag, prepends its entry to `CHANGELOG.md`, and updates the workspace version in
`Cargo.toml` and the local workspace packages in both `Cargo.lock` and `fuzz/Cargo.lock`.
Existing changelog entries are retained. Review the generated entry for accuracy and
compatibility notes, then commit the four files and open a normal PR. The command does
not commit, push, tag, or publish. PR CI and CodeQL run through the ordinary PR process.

This is local preparation, not an unattended release-PR service. No additional GitHub
credential is required. A future automated PR service needs a GitHub App identity (or
explicit CI dispatch wiring): PRs and tags created with `GITHUB_TOKEN` do not trigger
other workflows. Do not bypass the normal review and CI gates.

After the version PR passes review, CI and CodeQL and is merged, push its `vX.Y.Z` tag
using the normal maintainer credentials. The tag workflow first checks the workspace
and lock versions and requires one nonempty matching changelog entry. That reviewed
entry becomes the release body. It then builds the existing two-architecture candidate
artifacts and versioned fleet image. The GitHub release remains a draft with
`--latest=false`; the image receives only its version tag. Runtime qualification and
publication/promotion remain separate steps. Merging the changelog tooling itself does
not build or publish a new runtime version.

Qualify the exact candidate before explicitly publishing that version. Consumers pin the
published version and artifact identity with their matching application revision; a draft
build or a floating `latest` reference is not a qualification record. Host installation and
handover use the existing [Upgrade procedure](OPERATIONS.md#upgrade), with an explicit
`--release <version or URL>`.
