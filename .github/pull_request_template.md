<!--
Thanks for contributing! A few pointers before you submit:

- Scope small. One logical change per PR makes review fast.
- Tests + type-check + lint must be green before requesting review.
- If this touches osint-toolkit, verify the passive-by-default posture
  still holds (see ETHICS.md).
- Link the issue this PR resolves when applicable.
-->

## Summary

<!-- What does this change do? 1-3 short bullets. -->

- 

## Motivation

<!-- Why is this change worth making? Link the issue if there is one. -->

Closes #

## Implementation notes

<!-- Anything a reviewer would otherwise have to reverse-engineer: non-obvious
     trade-offs, design alternatives you rejected, migration concerns. -->

## Test plan

<!-- Prove it works. Automated is preferred; manual steps are OK when the
     automated path isn't practical (UI polish, docker integration). -->

- [ ] Unit / integration tests added or updated
- [ ] `pytest` + `npm test` green in affected workspaces
- [ ] `ruff check` / `mypy` / `eslint` clean in affected workspaces
- [ ] Manually exercised the change end-to-end (describe below)

## Checklist

- [ ] Change respects the scope described in [ETHICS.md](../ETHICS.md) - no
      features that ease unauthorized use
- [ ] No secrets, API keys or real target data committed
- [ ] `CHANGELOG.md` updated if this is user-visible
