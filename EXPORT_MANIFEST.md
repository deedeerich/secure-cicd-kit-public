# Export manifest

Produced by `scripts/export_for_adoption.py` on **2026-09-16**.

## This is a fresh tree, not a clone

**Git history was deliberately not exported.** Scrubbing a file does not scrub the commit that
introduced it, so a clone would carry every removed name and number along with it. This copy
starts from zero: `git init`, one commit, no inherited past.

## What the gate checked

13 forbidden patterns covering personal account identities, private consumer repository
names, finding counts attributable to a consumer, and former-employer references.

**Occurrences found at export time: 0.**

## What this gate does NOT cover

- Anything added after this export
- Binary files
- The originating repository's history, which still contains everything ever committed there
- Judgement. A pattern list catches what it was told to catch.

Re-run the gate before any onward distribution. It is cheap and it fails closed.
