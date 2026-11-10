"""Build a review inventory for migrating AppWorld tasks to AgentDojo.

The inventory is deliberately conservative. It identifies tasks whose source
APP dependencies can plausibly be represented by at least two AgentDojo APP
domains. A candidate is not considered migrated until fixtures, an executable
ground-truth plan, and task-specific final-state evaluation have been added.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

AGENTDOJO_APP_MAPPING: dict[str, str] = {
    "gmail": "workspace",
    "file_system": "workspace",
    "simple_note": "workspace",
    "todoist": "workspace",
    "venmo": "banking",
    "phone": "slack",
}

APPWORLD_APPS = (
    "amazon",
    "file_system",
    "gmail",
    "phone",
    "simple_note",
    "splitwise",
    "spotify",
    "todoist",
    "venmo",
)
INFRASTRUCTURE_APPS = frozenset({"admin", "api_docs", "supervisor"})
DATASET_NAMES = ("train", "dev", "test_normal", "test_challenge")


@dataclass(frozen=True)
class GeneratorInfo:
    generator_id: str
    source_file: str
    required_apps: tuple[str, ...]
    difficulty: int | None


@dataclass(frozen=True)
class InventoryRow:
    source_task_id: str
    source_dataset: str
    source_generator_id: str
    source_instruction: str
    source_difficulty: int | None
    source_num_apps: int | None
    source_num_apis: int | None
    source_solution_lines: int | None
    source_num_requirements: int
    source_no_op_fail_requirements: int
    source_no_op_pass_requirements: int
    source_required_apps: str
    source_app_inference: str
    changed_apps: str
    referenced_apps: str
    unsupported_apps: str
    target_domains: str
    target_domain_count: int
    target_domain_path: str
    preliminary_status: str
    review_reason: str
    spec_sha256: str
    evaluation_sha256: str


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def _split_apps(apps: list[str] | tuple[str, ...]) -> str:
    return "|".join(sorted(set(apps)))


def _read_dataset_ids(data_root: Path, dataset: str) -> list[str]:
    dataset_path = data_root / "datasets" / f"{dataset}.txt"
    if not dataset_path.exists():
        return []
    return [
        line.split(":", 1)[0].strip()
        for line in dataset_path.read_text(encoding="utf-8").splitlines()
        if line.split(":", 1)[0].strip()
    ]


def _generator_id(task_id: str) -> str:
    return task_id.rsplit("_", 1)[0]


def _decorator_generator_id(node: ast.ClassDef) -> str | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        if not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr != "register" or not decorator.args:
            continue
        value = decorator.args[0]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    return None


def _literal_string_tuple(node: ast.AST) -> tuple[str, ...] | None:
    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None
    if isinstance(value, tuple | list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    return None


def load_generator_metadata(generator_root: Path) -> dict[str, GeneratorInfo]:
    """Read generator declarations without importing AppWorld task code."""
    generators: dict[str, GeneratorInfo] = {}
    if not generator_root.exists():
        return generators
    for path in sorted(generator_root.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            generator_id = _decorator_generator_id(node)
            if generator_id is None:
                continue
            required_apps: tuple[str, ...] = ()
            difficulty: int | None = None
            for statement in node.body:
                if not isinstance(statement, ast.Assign | ast.AnnAssign):
                    continue
                target = statement.targets[0] if isinstance(statement, ast.Assign) else statement.target
                if not isinstance(target, ast.Name):
                    continue
                if target.id == "required_apps" and statement.value is not None:
                    parsed_apps = _literal_string_tuple(statement.value)
                    if parsed_apps is not None:
                        required_apps = parsed_apps
                elif target.id == "difficulty" and isinstance(statement.value, ast.Constant):
                    if isinstance(statement.value.value, int):
                        difficulty = statement.value.value
            generators[generator_id] = GeneratorInfo(
                generator_id=generator_id,
                source_file=path.name,
                required_apps=required_apps,
                difficulty=difficulty,
            )
    return generators


def _non_empty_db_apps(task_root: Path) -> tuple[str, ...]:
    dbs_root = task_root / "dbs"
    if not dbs_root.exists():
        return ()
    return tuple(
        sorted(
            path.stem
            for path in dbs_root.glob("*.jsonl")
            if path.stat().st_size > 0 and path.stem not in INFRASTRUCTURE_APPS
        )
    )


def _evaluation_apps(task_root: Path) -> tuple[str, ...]:
    evaluation_path = task_root / "ground_truth" / "evaluation.py"
    if not evaluation_path.exists():
        return ()
    text = evaluation_path.read_text(encoding="utf-8")
    return tuple(app for app in APPWORLD_APPS if re.search(rf"\b{re.escape(app)}\b", text))


def _sha256(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _count_requirements(task_root: Path) -> tuple[int, int, int]:
    test_data_path = task_root / "ground_truth" / "test_data.json"
    if not test_data_path.exists():
        return 0, 0, 0
    test_data = _read_json(test_data_path)
    if not isinstance(test_data, list):
        return 0, 0, 0
    labels = Counter(item.get("label") for item in test_data if isinstance(item, dict))
    return len(test_data), labels["no_op_fail"], labels["no_op_pass"]


def analyze_task(
    *,
    data_root: Path,
    dataset: str,
    task_id: str,
    generators: dict[str, GeneratorInfo],
) -> InventoryRow:
    task_root = data_root / "tasks" / task_id
    specs = _read_json(task_root / "specs.json")
    metadata_path = task_root / "ground_truth" / "metadata.json"
    metadata = _read_json(metadata_path) if metadata_path.exists() else {}
    generator_id = _generator_id(task_id)
    generator = generators.get(generator_id)
    changed_apps = _non_empty_db_apps(task_root)
    referenced_apps = _evaluation_apps(task_root)

    if generator is not None:
        required_apps = generator.required_apps
        source_app_inference = "generator"
    else:
        required_apps = tuple(sorted(set(changed_apps) | set(referenced_apps)))
        source_app_inference = "changed_dbs_or_evaluation"

    target_domains = tuple(
        dict.fromkeys(AGENTDOJO_APP_MAPPING[app] for app in required_apps if app in AGENTDOJO_APP_MAPPING)
    )
    unsupported_apps = tuple(app for app in required_apps if app not in AGENTDOJO_APP_MAPPING)
    requirement_count, no_op_fail_count, no_op_pass_count = _count_requirements(task_root)

    if unsupported_apps:
        status = "exclude_unsupported_app"
        reason = "A required APP has no defensible mapping into an AgentDojo domain."
    elif len(target_domains) < 2:
        status = "exclude_not_cross_agentdojo_app"
        reason = "Mapped requirements touch fewer than two AgentDojo APP domains."
    elif source_app_inference != "generator" and dataset in {"test_normal", "test_challenge"}:
        status = "hold_hidden_test"
        reason = (
            "The task has no released generator metadata; keep hidden tests out of "
            "development selection unless inference is manually validated."
        )
    else:
        status = "candidate_manual_review"
        reason = (
            "Mapped APP closure spans multiple AgentDojo domains; fixtures, primitive "
            "closure, evaluator semantics, and collateral effects still need review."
        )

    return InventoryRow(
        source_task_id=task_id,
        source_dataset=dataset,
        source_generator_id=generator_id,
        source_instruction=str(specs.get("instruction", "")),
        source_difficulty=metadata.get("difficulty"),
        source_num_apps=metadata.get("num_apps"),
        source_num_apis=metadata.get("num_apis"),
        source_solution_lines=metadata.get("num_solution_code_lines"),
        source_num_requirements=requirement_count,
        source_no_op_fail_requirements=no_op_fail_count,
        source_no_op_pass_requirements=no_op_pass_count,
        source_required_apps=_split_apps(required_apps),
        source_app_inference=source_app_inference,
        changed_apps=_split_apps(changed_apps),
        referenced_apps=_split_apps(referenced_apps),
        unsupported_apps=_split_apps(unsupported_apps),
        target_domains=_split_apps(target_domains),
        target_domain_count=len(target_domains),
        target_domain_path=" -> ".join(target_domains),
        preliminary_status=status,
        review_reason=reason,
        spec_sha256=_sha256(task_root / "specs.json"),
        evaluation_sha256=_sha256(task_root / "ground_truth" / "evaluation.py"),
    )


def build_inventory(data_root: Path, generator_root: Path) -> dict[str, Any]:
    if not (data_root / "tasks").exists():
        raise FileNotFoundError(f"AppWorld tasks directory not found under {data_root}")
    generators = load_generator_metadata(generator_root)
    rows: list[InventoryRow] = []
    dataset_task_counts: dict[str, int] = {}
    for dataset in DATASET_NAMES:
        task_ids = _read_dataset_ids(data_root, dataset)
        dataset_task_counts[dataset] = len(task_ids)
        for task_id in task_ids:
            rows.append(
                analyze_task(
                    data_root=data_root,
                    dataset=dataset,
                    task_id=task_id,
                    generators=generators,
                )
            )

    status_counts = Counter(row.preliminary_status for row in rows)
    domain_path_counts = Counter(
        row.target_domain_path for row in rows if row.preliminary_status == "candidate_manual_review"
    )
    unsupported_counts = Counter(app for row in rows for app in row.unsupported_apps.split("|") if app)
    return {
        "schema_version": 1,
        "source": {
            "benchmark": "AppWorld",
            "version": (data_root / "version.txt").read_text(encoding="utf-8").strip()
            if (data_root / "version.txt").exists()
            else "unknown",
            "data_root": str(data_root),
            "generator_root": str(generator_root),
            "generator_metadata_count": len(generators),
        },
        "summary": {
            "dataset_task_counts": dataset_task_counts,
            "status_counts": dict(sorted(status_counts.items())),
            "candidate_domain_paths": dict(domain_path_counts.most_common()),
            "unsupported_required_app_counts": dict(unsupported_counts.most_common()),
        },
        "app_mapping": AGENTDOJO_APP_MAPPING,
        "rows": [asdict(row) for row in rows],
    }


def write_inventory(inventory: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "inventory.json"
    csv_path = output_dir / "inventory.csv"
    json_path.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    rows = inventory["rows"]
    fieldnames = list(InventoryRow.__dataclass_fields__)
    with csv_path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return json_path, csv_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Inventory AppWorld tasks for AgentDojo cross-APP migration.")
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("external_data/appworld/data"),
        help="AppWorld data root containing datasets/ and tasks/.",
    )
    parser.add_argument(
        "--generator-root",
        type=Path,
        default=Path("external_data/appworld/generate/tasks/task_generators"),
        help="Released AppWorld task-generator module directory.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("external_data/appworld/migration"),
        help="Directory for inventory.json and inventory.csv.",
    )
    args = parser.parse_args()
    inventory = build_inventory(args.data_root, args.generator_root)
    json_path, csv_path = write_inventory(inventory, args.output_dir)
    print(json.dumps(inventory["summary"], ensure_ascii=False, indent=2))
    print(f"Wrote {json_path}")
    print(f"Wrote {csv_path}")


if __name__ == "__main__":
    main()
