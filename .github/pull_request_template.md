## Summary

What changes, in two or three bullets.

## Why

The problem, the finding ID it closes (`KRAKEN-SEC-001`, `AEGIS-REL-002`, ...)
or the incident it prevents. A reviewer a month later should understand the
motivation without reading the diff.

## Scope

Files or components touched, and anything a reader might expect but will not
find here.

## Verification

Commands actually run, with their result. Say explicitly what was not run and
why.

## Risk and rollback

- Runtime behaviour that changes for an existing deployment.
- How to roll back (revert of this commit, flag, or package downgrade).

## Checklist

- [ ] The relevant tests pass, and a regression test fails on the old code.
- [ ] Documentation updated when a contract, default or procedure changed.
- [ ] `CHANGELOG.md` has an entry for a user-visible change.
- [ ] No secrets, customer data or live malware samples in the diff.
- [ ] English only in code, comments and public text.
