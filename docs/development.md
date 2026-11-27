---
hide:
  - navigation
---

# Development setup

The project's local runtime and test environment is the Conda environment named
`agent`. Run all local commands below from the repository root:

```bash
conda create -n agent python=3.12 -y
conda activate agent
pip install -e ".[transformers,privacy]"
pip install pytest ruff pyright mkdocs-material python-dotenv
python -c "import sys; print(sys.executable)"
```

The last command must print the interpreter under
`C:\Users\<user>\.conda\envs\agent\`. The repository-level `.venv` is not the
canonical environment for this project.

`uv` remains used by CI and release packaging, but it is not the local launch
command for this repository.

## Install the dev packages, lint, test, typecheck

- Lint with `python -m ruff check --fix .`
- Format with `python -m ruff format`
- Test with `python -m pytest tests`
- Run the static type checker with `python -m pyright`

## Running the docs

After activating `agent`, run `python -m mkdocs serve`. The docs will be
available at `http://localhost:8000`.
