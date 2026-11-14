# Contributing

## License and sign-off

By contributing, you agree to license your contribution under
**AGPL-3.0-only** and to the Developer Certificate of Origin (DCO) 1.1.
Sign every commit with:

```bash
git commit -s
```

There is no CLA.

## Commit rules

- Use Conventional Commits: `feat(scope): ...`, `fix(scope): ...`,
  `docs(scope): ...`, `test(scope): ...`, `chore(scope): ...`.
- One commit, one type. Do not mix a refactor with a fix.
- Do not mention vendors or products used only as internal benchmarks.
- Do not add co-author lines or AI attribution.
- Explain **why** the change is needed, not only what changed.
- Reference the finding ID when the commit closes one
  (for example `KRAKEN-SEC-001`).

## Pull requests

- One finding per pull request.
- Include a regression test that fails on the old code and passes on the new
  code.
- Run the relevant tests. Do not skip, weaken or delete assertions to make a
  check pass.
- Do not commit secrets, real customer data or live malware samples.
- Update the documentation when a contract, default or procedure changes.
- Keep the diff focused; a separate pull request is better than a mixed one.

## Development checks

The exact commands depend on the component:

```bash
# Brain
cd aegis-brain && pytest -q

# Guard / Link
cd aegis-guard && mvn -B test
cd aegis-link && mvn -B test

# Frontend
cd frontend && npm ci && npm run lint && npx tsc -b --noEmit && npm run build
```

## Security issues

Do not open a public issue. Follow [`SECURITY.md`](SECURITY.md).
