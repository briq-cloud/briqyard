# ADR 0105: A ruleset protects main

2026-11-04 · Accepted

## Context

`main` had no protection. "Never push to `main`" and "merge once CI and CodeQL pass" held by convention only, and agents work with an admin token. One account has access to the repository, and GitHub does not let an author approve their own PR: PRs #145, #148 and #149 each have 0 GitHub reviews.

## Decisions

Ruleset `main` (id 26546765), on the default branch, active.

| Rule | Setting |
|---|---|
| Deletion, force push | Refused |
| Pull request | Required, 0 approvals; `require_extra_approval_for_unattributed_changes` stays at GitHub's default, `true` |
| Merge method | Squash only |
| Required checks | `check` (GitHub Actions), `CodeQL` (GitHub Advanced Security) |
| Branch up to date before merge | Not required |
| Bypass | Nobody |

**No required approval.** It cannot be met with one account. A bypass would be used on every merge and enforce nothing. A reviewer's approval stays a rule of `AGENTS.md`.

**No bypass.** The rules bind agents using the admin token too. An admin can still disable the ruleset deliberately in an emergency.

**`check` and `CodeQL` only.** Both report on a PR that only changes docs (#141). The `native` workflow filters on paths, so a required job of it would never report on such a PR and would block it. Its jobs are also 18 to 23 minutes and stay not required (`docs/DEVELOPMENT.md`). `CodeQL` is required instead of each `Analyze (…)` job, so the required list does not follow the set of languages.

**Each check is pinned to its app,** so another workflow or app cannot satisfy it by reporting the same name.

**No up-to-date requirement.** A conflicting PR is already updated on its own branch. Requiring every PR to be current would re-run its checks after each merge.

## Consequences

- A push to `main`, a merge with `check` or `CodeQL` failing, and a merge commit are refused, for everyone.
- Renaming the `check` job blocks every PR until the ruleset follows.
- GitHub does not enforce review. Enforcing it needs a second account or a GitHub App with write access, and a new ADR.
- The ruleset lives in GitHub, not in this repository: `gh api repos/briq-cloud/briqyard/rulesets/26546765` shows it.
