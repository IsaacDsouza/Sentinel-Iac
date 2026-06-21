# Contributing

## Development Setup

```bash
uv sync --all-groups
uv run pre-commit install
```

## Running Checks

```bash
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy --strict src/
uv run pytest tests/ -v
```

## Eval Harness

```bash
uv run python evals/run_eval.py
```

## Adding a Scanner

1. Create `src/sentinel/scanners/<name>.py` implementing the `Scanner` protocol
2. Add to `SCANNERS` list in `src/sentinel/scanners/__init__.py`
3. Add cross-engine equivalences to `equivalences.py`
4. Add test fixture to `evals/fixtures/`
5. Add expected findings to `evals/golden.yaml`
