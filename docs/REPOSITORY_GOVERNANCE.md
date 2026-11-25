# Repository governance

This document defines the minimum GitHub controls for the public
`probantia-sas/easyconstat-evidence-verifier` repository. Repository settings
remain an administrative operation and are not changed by the build.

## Default branch

`main` is the only default branch. Configure a GitHub ruleset targeting this
branch with the following controls:

- require a pull request before merging;
- require one independent approval when a second maintainer is available
  and dismiss stale approvals after new commits; while there is only one
  maintainer, keep pull requests mandatory with zero required approvals;
- require all review conversations to be resolved;
- require the `Maven verification` status check to pass;
- require branches to be up to date before merging;
- require linear history once squash or rebase merging is enabled;
- block force pushes and branch deletion;
- do not grant routine bypass permission to a deploy key.

The required status check must be selected from a successful recent workflow
run rather than entered as an unverified free-form name.

Signed commits should become mandatory only after PROBANTIA has established
developer commit-signing keys and a documented recovery procedure. Enabling
that rule prematurely would replace a controlled publication process with an
operational lockout risk.

## Release tags

Use two repository rulesets for tags matching `v*`:

- deny updates and deletions, with no bypass;
- restrict creation only, with repository administrators as the only bypass;
- create a tag only from a commit already present on protected `main`;
- publish a GitHub release only after independent verification of the signed
  release manifest.

The Git tag and GitHub release are distribution metadata. The detached
Ed25519 signature of `release-manifest.json` remains the verifier release's
portable authenticity control.

## Administrative access

- use named GitHub accounts with two-factor authentication;
- keep repository administrators to the minimum necessary;
- use the repository-scoped deploy key only for source publication;
- never store the release private key or its passphrase in GitHub Actions;
- review deploy keys, collaborators, rulesets and workflow permissions at
  least every six months.

Emergency bypasses must be exceptional, documented and followed by a normal
pull-request review of the resulting commit.

## First public source publication

Treat the qualification repository, its existing history and its CI logs
as private. Reviewing and updating the working tree does not sanitize
earlier commits or logs.

Start the publication repository with a reviewed source snapshot, fresh
history and no inherited CI logs. Review tracked files, fixtures and the new
CI output before publication. Confirm GitHub enforces the `main` and release
tag rules before advertising or distributing the verifier. Repository-level
rules on a private GitHub Free organization repository are not enforced.
