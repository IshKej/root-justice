# Contributing to Root Justice

Thanks for your interest in improving Root Justice (Artex Antidote). A few
project rules keep the codebase predictable and safe.

## Running the tests

The full suite runs with the standard library's `unittest` — no test runner to
install:

```bash
python -m unittest discover -s tests
```

Tests are deterministic and offline. Please keep them that way: no network
calls, no reliance on wall-clock time or external services.

## Standard-library only

The `artex_antidote` package has **no runtime third-party dependencies** — it is
Python standard library only (see the package design notes). Please do not add a
runtime dependency. Optional, clearly-gated extras (declared under
`project.optional-dependencies` in `pyproject.toml`) are the only exception, and
the core must still work without them.

## Defensive scope

Root Justice is **strictly defensive**. Contributions must not add offensive or
"hack-back" capability, must not reach out to third-party hosts, and must keep
the fail-open guarantee (an internal error allows traffic rather than taking
down the protected app). Keep docstrings and user-facing wording honest — do not
overstate what a feature does.

## Backward compatibility

Keep changes backward compatible. New parameters should be **keyword-only with
safe defaults** so existing callers and the public import surface keep working.
Add tests for any new behavior you introduce, and make sure the full suite stays
green before opening a pull request.

## Submitting changes

1. Create a branch and make your change.
2. Add or update tests for the behavior.
3. Run `python -m unittest discover -s tests` and confirm everything passes.
4. Open a pull request describing the change and its defensive rationale.
