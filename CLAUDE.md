# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AgentDojo is a dynamic environment to evaluate prompt injection attacks and defenses for LLM agents. It provides a benchmarking framework for testing LLM agents against various attack scenarios while implementing different defense mechanisms.

## Key Commands

### Development Setup
```bash
# Local development uses the Conda environment named `agent`
conda create -n agent python=3.12 -y
conda activate agent
pip install -e ".[transformers,privacy]"
pip install pytest ruff pyright mkdocs-material python-dotenv
```

### Testing
```bash
# Run all tests
python -m pytest tests

# Run a specific test file
python -m pytest tests/test_benchmark.py

# Run tests with verbose output
python -m pytest -v tests
```

### Linting and Type Checking
```bash
# Run linter with auto-fix
python -m ruff check --fix .

# Format code
python -m ruff format

# Run type checker
python -m pyright
```

### Running the Benchmark
```bash
# Run benchmark with specific parameters
python -m agentdojo.scripts.benchmark -s workspace -ut user_task_0 \
    -ut user_task_1 --model gpt-4o-2024-05-13 \
    --defense tool_filter --attack tool_knowledge

# Run benchmark on all suites and tasks
python -m agentdojo.scripts.benchmark --model gpt-4o-2024-05-13 \
    --defense tool_filter --attack tool_knowledge

# Get help on benchmark options
python -m agentdojo.scripts.benchmark --help
```

### Documentation
```bash
# Build and serve docs locally
python -m mkdocs serve  # Available at http://localhost:8000

# Deploy docs to GitHub Pages
python -m mkdocs gh-deploy --force

# Generate results table for docs
python util_scripts/create_results_table.py
```

## Code Architecture

### Core Components

**Agent Pipeline** (`src/agentdojo/agent_pipeline/`)
- Implements the core agent execution pipeline with support for different LLMs (OpenAI, Anthropic, Cohere, Google)
- Includes defense mechanisms (tool filters, prompt guards, etc.) that can be composed together
- Handles tool execution and message passing between components

**Attack System** (`src/agentdojo/attacks/`)
- Base attack classes for implementing various prompt injection strategies
- Baseline attacks including tool knowledge, important instructions, and system prompt attacks
- DOS (Denial of Service) attack implementations
- Attack registration and loading system for custom attacks

**Task Suite** (`src/agentdojo/task_suite/`)
- Framework for defining user tasks and injection tasks
- Task validation and execution logic
- Support for multi-step tasks with dependencies

**Functions Runtime** (`src/agentdojo/functions_runtime.py`)
- Runtime for executing tool functions in a sandboxed environment
- Function registration and validation
- Stateful and stateless function execution support

**Benchmark System** (`src/agentdojo/benchmark.py`)
- Main benchmarking logic for evaluating agents against attacks
- Result collection and analysis
- Integration with various suites (workspace, slack, banking, etc.)

### Default Suites

The project includes several pre-built task suites in `src/agentdojo/default_suites/`:
- **workspace**: Office productivity tasks
- **slack**: Slack-like messaging tasks
- **banking**: Financial transaction tasks
- **travel**: Travel booking and planning tasks
- **webbase**: Web-based interaction tasks

Each suite contains user tasks (legitimate operations) and injection tasks (attack scenarios).

### Key Design Patterns

1. **Pipeline Composition**: Agent pipelines are built by composing elements (LLMs, defenses, tools) that process messages sequentially.

2. **Tool Registration**: Functions are registered as tools with automatic schema generation from type hints and docstrings.

3. **Attack/Defense Separation**: Attacks and defenses are independent components that can be mixed and matched for evaluation.

4. **Message-Based Communication**: All components communicate through a standardized message format supporting different roles (user, assistant, tool).

## Code Style Guidelines

### Type Annotations
- Use modern Python typing syntax (Python 3.10+):
  - `list[str]` instead of `List[str]`
  - `dict[str, int]` instead of `Dict[str, int]`
  - `int | None` instead of `Optional[int]`
  - `str | int` instead of `Union[str, int]`

### Import Style
- **Always use module-level imports only** - never use local imports inside functions
- Place all imports at the top of the file
- Follow standard import ordering: standard library, third-party, local

## Testing Approach

Tests are organized by component in the `tests/` directory. Key test areas:
- Agent pipeline components and LLM integrations
- Attack and defense implementations
- Functions runtime and tool execution
- Benchmark logic and result processing

Always run the full test suite before committing changes:
```bash
conda activate agent
python -m pytest tests
python -m ruff check .
python -m pyright
```
