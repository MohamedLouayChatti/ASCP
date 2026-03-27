# DLP Module Development

## Philosophy

This branch is module-scoped. Development artifacts should stay under `dlp/` whenever possible to reduce merge conflicts when integrating into `main`.

## Local Commands

```bash
python -m pytest dlp/tests -v
python -m pytest dlp/tests -v --cov=dlp --cov-report=term-missing
```

## Optional Developer Dependencies

Use `dlp/requirements-dev.txt` if your environment does not already provide tools.

```bash
pip install -r dlp/requirements-dev.txt
```

## CI Template

A reusable CI template is provided at `dlp/ci/workflows/tests.yml`.

Important: GitHub Actions only runs from `.github/workflows/` at repository root. In the target monorepo, copy or adapt this template there.
