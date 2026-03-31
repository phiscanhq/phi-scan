## Summary

<!-- Describe what this PR does and why. Reference the PLAN.md task number. -->

Closes #<!-- issue number if applicable -->

---

## Type of change

- [ ] Bug fix
- [ ] New feature / detection layer
- [ ] Output format
- [ ] Documentation
- [ ] CI/CD / tooling
- [ ] Refactor (no behaviour change)

---

## Checklist

- [ ] `make lint` passes (`ruff check . --fix && ruff format .`)
- [ ] `make typecheck` passes (zero mypy errors)
- [ ] `make test` passes (all tests pass, coverage ≥ 80%)
- [ ] No raw PHI values in any new test fixtures (synthetic data only)
- [ ] New test fixtures under `tests/fixtures/phi/` begin with `# Synthetic PHI fixture:` and `# Expected findings:` headers
- [ ] No `Co-Authored-By:` tags in any commit message
- [ ] CHANGELOG.md updated if this is a user-visible change
- [ ] Documentation updated if this changes CLI behaviour or configuration

---

## Testing

<!-- Describe how you tested this change. -->

---

## Security notes

<!-- Does this PR touch the detection pipeline, audit log, or output formatting?
     If so, confirm that no raw PHI values are stored, logged, or displayed. -->
