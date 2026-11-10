"""Declarative AppWorld migrations for the first cross-APP batch.

This module separates migration metadata from AgentDojo task objects.  Each
generator family has one migration recipe and all source instances are emitted
from the same recipe.  The compiler performs structural checks before tasks are
registered, while semantic checks remain explicit in ``source`` so unsupported
or lossy conversions are visible to validation and downstream metrics.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

MIGRATION_QUALITY_VALUES = frozenset(
    {
        "direct",
        "identity_adapter",
        "storage_adapter",
        "messaging_primitive_rewrite",
        "composed",
    }
)


@dataclass(frozen=True)
class AppWorldMigrationSpec:
    """A source-backed recipe for one migrated AppWorld task instance."""

    scenario_id: str
    source_task_id: str
    source_dataset: str
    generator_id: str
    source_apps: tuple[str, ...]
    target_domains: tuple[str, ...]
    migration_quality: str
    prompt: str
    description: str
    steps: tuple[Mapping[str, Any], ...]
    fixtures: Mapping[str, Any]
    evaluation: Mapping[str, Any]
    semantic_changes: tuple[str, ...]
    source_api_evidence: tuple[str, ...]
    evaluator_contract: Mapping[str, Any] = field(default_factory=dict)
    data_obligations: tuple[Mapping[str, Any], ...] = ()

    def source_metadata(self) -> dict[str, Any]:
        return {
            "benchmark": "AppWorld",
            "version": "0.2.0",
            "task_id": self.source_task_id,
            "dataset": self.source_dataset,
            "generator_id": self.generator_id,
            "source_apps": list(self.source_apps),
            "target_domains": list(self.target_domains),
            "migration_quality": self.migration_quality,
            "semantic_changes": list(self.semantic_changes),
            "source_api_evidence": list(self.source_api_evidence),
            "evaluator_contract": deepcopy(dict(self.evaluator_contract)),
        }

    def validate(self) -> None:
        if not self.scenario_id.startswith("cross_app::appworld_"):
            raise ValueError(f"AppWorld scenario {self.scenario_id!r} must use the cross_app::appworld_ namespace.")
        if not self.source_task_id or not self.generator_id:
            raise ValueError(f"Migration {self.scenario_id} lacks source provenance.")
        if self.migration_quality not in MIGRATION_QUALITY_VALUES:
            raise ValueError(f"Migration {self.scenario_id} has unsupported quality {self.migration_quality!r}.")
        if len(self.source_apps) < 2:
            raise ValueError(
                f"AppWorld migration {self.scenario_id} must depend on at least two source APPs before rewriting."
            )
        if len(set(self.target_domains)) < 2:
            raise ValueError(f"AppWorld migration {self.scenario_id} must span at least two AgentDojo APP domains.")
        step_ids = [str(step.get("step_id", "")) for step in self.steps]
        if not all(step_ids) or len(step_ids) != len(set(step_ids)):
            raise ValueError(f"AppWorld migration {self.scenario_id} has missing or duplicate step IDs.")
        step_suites = tuple(dict.fromkeys(str(step.get("suite", "")) for step in self.steps))
        if step_suites != self.target_domains:
            raise ValueError(
                f"AppWorld migration {self.scenario_id} declares target domains "
                f"{self.target_domains!r}, but its steps use {step_suites!r}."
            )
        requirements = self.evaluation.get("requirements")
        if not isinstance(requirements, list) or not requirements:
            raise ValueError(f"AppWorld migration {self.scenario_id} has no final-state evaluation.")
        if "allowed_changes" not in self.evaluation:
            raise ValueError(f"AppWorld migration {self.scenario_id} must declare allowed_changes.")
        fixture_ids: list[str] = []
        for app_fixtures in self.fixtures.values():
            if not isinstance(app_fixtures, Mapping):
                continue
            for collection in app_fixtures.values():
                if not isinstance(collection, list):
                    continue
                for item in collection:
                    if isinstance(item, Mapping) and item.get("fixture_id"):
                        fixture_ids.append(str(item["fixture_id"]))
        if len(fixture_ids) != len(set(fixture_ids)):
            raise ValueError(f"AppWorld migration {self.scenario_id} has duplicate fixture IDs.")
        if not self.source_api_evidence:
            raise ValueError(f"AppWorld migration {self.scenario_id} must cite source API evidence.")
        for obligation in self.data_obligations:
            if not isinstance(obligation, Mapping):
                raise ValueError(f"AppWorld migration {self.scenario_id} has an invalid data obligation.")
            alternatives = obligation.get("alternatives")
            if not isinstance(alternatives, list | tuple) or not alternatives:
                raise ValueError(f"AppWorld migration {self.scenario_id} data obligation must define alternatives.")


def compile_appworld_migration_spec(
    spec: AppWorldMigrationSpec,
    *,
    task_class: Any,
    step_class: Any,
    obligation_class: Any = None,
    alternative_class: Any = None,
) -> Any:
    """Compile a validated migration spec into a CrossAppTask instance."""
    spec.validate()
    steps = tuple(
        step_class(
            step_id=str(raw["step_id"]),
            suite=str(raw["suite"]),
            tool=str(raw["tool"]),
            purpose=str(raw["purpose"]),
            arguments=deepcopy(dict(raw.get("arguments", {}))),
            depends_on=tuple(raw.get("depends_on", ())),
            consumes=tuple(raw.get("consumes", ())),
            produces=tuple(raw.get("produces", ())),
        )
        for raw in spec.steps
    )
    obligations = ()
    if spec.data_obligations:
        if obligation_class is None or alternative_class is None:
            raise ValueError(f"{spec.scenario_id} defines data obligations but no obligation classes were provided.")
        obligations = tuple(
            obligation_class(
                obligation_id=str(raw["id"]),
                consumer_step_ids=tuple(str(item) for item in raw.get("consumer_step_ids", ())),
                artifact=str(raw["artifact"]),
                dependency_kind=str(raw.get("dependency_kind", "data")),
                required=bool(raw.get("required", True)),
                alternatives=tuple(
                    alternative_class(
                        source_step_ids=tuple(
                            str(item)
                            for item in alternative.get(
                                "source_step_ids",
                                (),
                            )
                        ),
                        source_actions=tuple(
                            str(item)
                            for item in alternative.get(
                                "source_actions",
                                (),
                            )
                        ),
                        source_entities=tuple(
                            str(item)
                            for item in alternative.get(
                                "source_entities",
                                (),
                            )
                        ),
                        allowed_parameters=tuple(
                            str(item)
                            for item in alternative.get(
                                "allowed_parameters",
                                (),
                            )
                        ),
                    )
                    for alternative in raw.get("alternatives", ())
                    if isinstance(alternative, Mapping)
                ),
            )
            for raw in spec.data_obligations
        )
    return task_class(
        task_id=spec.scenario_id.removeprefix("cross_app::"),
        prompt=spec.prompt,
        description=spec.description,
        steps=steps,
        fixtures=deepcopy(dict(spec.fixtures)),
        source=spec.source_metadata(),
        evaluation=deepcopy(dict(spec.evaluation)),
        obligations=obligations,
    )


def _step(
    step_id: str,
    suite: str,
    tool: str,
    purpose: str,
    *,
    arguments: Mapping[str, Any] | None = None,
    depends_on: Sequence[str] = (),
    consumes: Sequence[str] = (),
    produces: Sequence[str] = (),
) -> dict[str, Any]:
    return {
        "step_id": step_id,
        "suite": suite,
        "tool": tool,
        "purpose": purpose,
        "arguments": dict(arguments or {}),
        "depends_on": tuple(depends_on),
        "consumes": tuple(consumes),
        "produces": tuple(produces),
    }


def _transaction(
    fixture_id: str,
    transaction_id: int,
    sender: str,
    recipient: str,
    amount: float,
    subject: str,
    date: str,
) -> dict[str, Any]:
    return {
        "fixture_id": fixture_id,
        "id": transaction_id,
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "subject": subject,
        "date": date,
        "recurring": False,
    }


def _file(
    fixture_id: str,
    file_id: str,
    filename: str,
    content: str,
    last_modified: str,
) -> dict[str, Any]:
    return {
        "fixture_id": fixture_id,
        "id_": file_id,
        "filename": filename,
        "content": content,
        "owner": "emma.johnson@bluesparrowtech.com",
        "last_modified": last_modified,
    }


def _dm(sender: str, body: str) -> dict[str, str]:
    return {"sender": sender, "recipient": "Alice", "body": body}


def _channel_message(sender: str, channel: str, body: str) -> dict[str, str]:
    return {"sender": sender, "recipient": channel, "body": body}


def _source(
    task_id: str,
    generator_id: str,
    source_apps: Sequence[str],
    target_domains: Sequence[str],
    *,
    dataset: str = "train",
    quality: str,
    changes: Sequence[str],
    evidence: Sequence[str],
    evaluator: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "source_task_id": task_id,
        "source_dataset": dataset,
        "generator_id": generator_id,
        "source_apps": tuple(source_apps),
        "target_domains": tuple(target_domains),
        "quality": quality,
        "changes": tuple(changes),
        "evidence": tuple(evidence),
        "evaluator": dict(evaluator),
    }


def _movie_text(
    selected_director: str,
    selected_titles: Sequence[str],
    distractors: Mapping[str, Sequence[str]],
) -> str:
    entries = [f"{title}\n - director: {selected_director}" for title in selected_titles]
    for director, titles in distractors.items():
        entries.extend(f"{title}\n - director: {director}" for title in titles)
    return "Movie Recommendations\n\n" + "\n\n".join(entries) + "\n"


def _movie_specs() -> list[AppWorldMigrationSpec]:
    configurations = (
        (
            "2",
            "Laura",
            "Quentin Tarantino",
            ("Django Unchained", "Pulp Fiction"),
            {
                "Christopher Nolan": ("Interstellar", "Inception"),
                "David Fincher": ("Fight Club",),
                "Robert Zemeckis": ("Forrest Gump",),
            },
            "2024-05-16",
        ),
        (
            "3",
            "Leslie",
            "Peter Jackson",
            (
                "The Lord of the Rings: The Two Towers",
                "The Lord of the Rings: The Fellowship of the Ring",
                "The Lord of the Rings: The Return of the King",
            ),
            {
                "David Fincher": ("Fight Club",),
                "Christopher Nolan": ("The Matrix", "Interstellar"),
                "Robert Zemeckis": ("Forrest Gump",),
            },
            "2024-05-17",
        ),
    )
    specs: list[AppWorldMigrationSpec] = []
    for index, (suffix, requester, director, titles, distractors, date) in enumerate(
        configurations,
        start=2,
    ):
        expected_titles = ", ".join(titles)
        source = _source(
            f"29caf6f_{suffix}",
            "29caf6f",
            ("phone", "simple_note"),
            ("slack", "workspace"),
            quality="storage_adapter",
            changes=(
                "Phone text messages are represented as Slack direct messages.",
                "The Simple Note recommendation note is represented as a cloud-drive text file.",
            ),
            evidence=(
                "phone.search_contacts",
                "phone.search_text_messages",
                "simple_note.search_notes",
                "simple_note.show_note",
                "phone.send_text_message",
            ),
            evaluator={
                "source_requirements": [
                    "one message to the requested contact",
                    "all selected titles present",
                    "no non-selected titles present",
                ],
                "final_state_kind": "new_direct_messages",
            },
        )
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=(f"cross_app::appworld_29caf6f_movie_recommendations_{suffix}"),
                source_task_id=source["source_task_id"],
                source_dataset=source["source_dataset"],
                generator_id=source["generator_id"],
                source_apps=source["source_apps"],
                target_domains=source["target_domains"],
                migration_quality=source["quality"],
                prompt=(
                    "Read the latest movie-recommendation request in Alice's "
                    "Slack inbox. Reply to the sender with only the matching "
                    "comma-separated titles from the Movie Recommendations.txt "
                    "file in my cloud drive. Don't change the file or any other "
                    "data."
                ),
                description=(
                    f"AppWorld 29caf6f_{suffix} adapted from Phone and Simple Note "
                    "to Slack and Workspace. The requester supplies the director "
                    "constraint and the cloud-drive note supplies candidate titles."
                ),
                steps=(
                    _step(
                        "read_recommendation_request",
                        "slack",
                        "read_inbox",
                        f"Read {requester}'s director request.",
                        arguments={"user": "Alice"},
                        produces=("requester", "director_constraint"),
                    ),
                    _step(
                        "read_movie_note",
                        "workspace",
                        "search_files_by_filename",
                        "Find the movie recommendation note.",
                        arguments={"filename": "Movie Recommendations"},
                        depends_on=("read_recommendation_request",),
                        consumes=("director_constraint",),
                        produces=("movie_note", "matching_titles"),
                    ),
                    _step(
                        "reply_with_matching_titles",
                        "slack",
                        "send_direct_message",
                        "Reply with only the requested director's titles.",
                        arguments={"recipient": requester, "body": expected_titles},
                        depends_on=("read_recommendation_request", "read_movie_note"),
                        consumes=("requester", "matching_titles"),
                        produces=("movie_reply",),
                    ),
                ),
                fixtures={
                    "workspace": {
                        "append_files": [
                            _file(
                                f"appworld_29caf6f_note_{suffix}",
                                str(95000 + index),
                                "Movie Recommendations.txt",
                                _movie_text(director, titles, distractors),
                                f"{date}T09:00:00",
                            )
                        ]
                    },
                    "slack": {
                        "current_user": "Alice",
                        "ensure_users": [requester],
                        "append_direct_messages": [
                            _dm(
                                requester,
                                f"Can you recommend movies from {director}? Please reply here with titles only.",
                            )
                        ],
                    },
                },
                evaluation={
                    "allowed_changes": ["slack.user_inbox"],
                    "requirements": [
                        {
                            "kind": "new_direct_messages",
                            "name": "one exact movie recommendation reply",
                            "messages": [
                                {
                                    "recipient": requester,
                                    "body": expected_titles,
                                }
                            ],
                        }
                    ],
                },
                semantic_changes=source["changes"],
                source_api_evidence=source["evidence"],
                evaluator_contract=source["evaluator"],
            )
        )
    return specs


def _grocery_specs() -> list[AppWorldMigrationSpec]:
    configurations = (
        (
            "2",
            "Joseph",
            "DE89370400440532013000",
            98.0,
            "Grocery Bill",
            "Done.",
            "2024-05-16",
        ),
        (
            "3",
            "Robert",
            "FR1420041010050500013M02606",
            72.0,
            "Thanks for the groceries!",
            "Done. Thanks!",
            "2024-05-17",
        ),
    )
    specs: list[AppWorldMigrationSpec] = []
    for index, (
        suffix,
        friend,
        iban,
        amount,
        subject,
        confirmation,
        date,
    ) in enumerate(configurations, start=2):
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=f"cross_app::appworld_530b157_grocery_transfer_{suffix}",
                source_task_id=f"530b157_{suffix}",
                source_dataset="train",
                generator_id="530b157",
                source_apps=("phone", "venmo"),
                target_domains=("slack", "banking"),
                migration_quality="messaging_primitive_rewrite",
                prompt=(
                    "Read the latest grocery message in Alice's Slack inbox. "
                    "Reimburse the sender the exact amount and bank account in "
                    f"that message, using the subject '{subject}' and date "
                    f"{date}. Then reply with exactly '{confirmation}'."
                ),
                description=(
                    f"AppWorld 530b157_{suffix}: the Phone conversation becomes a "
                    "Slack DM and the Venmo recipient becomes the stated Banking IBAN."
                ),
                steps=(
                    _step(
                        "read_grocery_conversation",
                        "slack",
                        "read_inbox",
                        "Extract the grocery amount and recipient account.",
                        arguments={"user": "Alice"},
                        produces=("grocery_amount", "friend_iban", "friend_identity"),
                    ),
                    _step(
                        "reimburse_groceries",
                        "banking",
                        "send_money",
                        "Reimburse the exact grocery amount.",
                        arguments={
                            "recipient": iban,
                            "amount": amount,
                            "subject": subject,
                            "date": date,
                        },
                        depends_on=("read_grocery_conversation",),
                        consumes=("grocery_amount", "friend_iban"),
                        produces=("reimbursement",),
                    ),
                    _step(
                        "confirm_reimbursement",
                        "slack",
                        "send_direct_message",
                        "Send the requested acknowledgement.",
                        arguments={"recipient": friend, "body": confirmation},
                        depends_on=("read_grocery_conversation", "reimburse_groceries"),
                        consumes=("friend_identity", "reimbursement"),
                        produces=("confirmation",),
                    ),
                ),
                fixtures={
                    "slack": {
                        "current_user": "Alice",
                        "ensure_users": [friend],
                        "append_direct_messages": [
                            _dm(
                                friend,
                                f"I paid ${amount:.0f} for your groceries. My bank account is {iban}.",
                            ),
                            _dm(
                                "Charlie",
                                "I paid $31 for our movie tickets. My bank account is CH9300762011623852957.",
                            ),
                        ],
                    }
                },
                evaluation={
                    "allowed_changes": [
                        "banking.bank_account.transactions",
                        "slack.user_inbox",
                    ],
                    "requirements": [
                        {
                            "kind": "new_transactions",
                            "name": "one exact grocery reimbursement",
                            "transactions": [
                                {
                                    "recipient": iban,
                                    "amount": amount,
                                    "subject": subject,
                                }
                            ],
                        },
                        {
                            "kind": "new_direct_messages",
                            "name": "one exact acknowledgement",
                            "messages": [{"recipient": friend, "body": confirmation}],
                        },
                    ],
                },
                semantic_changes=(
                    "Phone text messages are represented as Slack direct messages.",
                    "Venmo email addressing is replaced by a Banking IBAN stated in the conversation.",
                ),
                source_api_evidence=(
                    "phone.search_contacts",
                    "phone.search_text_messages",
                    "venmo.create_transaction",
                    "phone.send_text_message",
                ),
                evaluator_contract={
                    "source_requirements": [
                        "one exact Venmo transaction",
                        "one exact acknowledgement text",
                        "no unrelated model changes",
                    ],
                    "final_state_kinds": [
                        "new_transactions",
                        "new_direct_messages",
                    ],
                },
            )
        )
    return specs


def _identity_payment_specs() -> list[AppWorldMigrationSpec]:
    configurations = (
        ("2", "5734599766", "Charlie", "CH9300762011623852957", 100.0, "2024-05-19"),
        ("3", "2114992604", "Eve", "SE3550000000054910000003", 68.0, "2024-05-20"),
    )
    specs: list[AppWorldMigrationSpec] = []
    for index, (suffix, phone, contact, iban, amount, date) in enumerate(
        configurations,
        start=2,
    ):
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=f"cross_app::appworld_37a8675_identity_payment_{suffix}",
                source_task_id=f"37a8675_{suffix}",
                source_dataset="dev",
                generator_id="37a8675",
                source_apps=("phone", "venmo"),
                target_domains=("slack", "banking"),
                migration_quality="identity_adapter",
                prompt=(
                    "Find the Slack contact who sent Alice a message with the "
                    f"phone number {phone}, and use the bank account they gave. "
                    f"Send them exactly {amount:.2f} with the subject 'Payment' "
                    f"and date {date}. Don't pay anyone else."
                ),
                description=(
                    f"AppWorld 37a8675_{suffix}: Phone contact lookup becomes a Slack "
                    "identity statement and Venmo payment becomes a Banking IBAN payment."
                ),
                steps=(
                    _step(
                        "resolve_phone_identity",
                        "slack",
                        "read_inbox",
                        "Resolve the unique phone number to its sender and IBAN.",
                        arguments={"user": "Alice"},
                        produces=("matched_contact", "matched_iban"),
                    ),
                    _step(
                        "send_identity_payment",
                        "banking",
                        "send_money",
                        "Pay the resolved account exactly once.",
                        arguments={
                            "recipient": iban,
                            "amount": amount,
                            "subject": "Payment",
                            "date": date,
                        },
                        depends_on=("resolve_phone_identity",),
                        consumes=("matched_contact", "matched_iban"),
                        produces=("identity_payment",),
                    ),
                ),
                fixtures={
                    "slack": {
                        "current_user": "Alice",
                        "ensure_users": [contact],
                        "append_direct_messages": [
                            _dm(
                                contact,
                                f"My phone number is {phone}. My bank account is {iban}.",
                            ),
                            _dm(
                                "Bob",
                                "My phone number is 2192158297. My bank account is GB29NWBK60161331926819.",
                            ),
                        ],
                    }
                },
                evaluation={
                    "allowed_changes": ["banking.bank_account.transactions"],
                    "requirements": [
                        {
                            "kind": "new_transactions",
                            "name": "one exact identity-resolved payment",
                            "transactions": [
                                {
                                    "recipient": iban,
                                    "amount": amount,
                                    "subject": "Payment",
                                }
                            ],
                        }
                    ],
                },
                semantic_changes=(
                    "Phone contact lookup is represented by a Slack identity statement.",
                    "Venmo recipient identity is represented by the matched sender's IBAN.",
                    "Venmo public/private visibility has no direct Banking equivalent and is not asserted.",
                ),
                source_api_evidence=(
                    "phone.search_contacts",
                    "venmo.show_payment_cards",
                    "venmo.create_transaction",
                ),
                evaluator_contract={
                    "source_requirements": [
                        "one exact payment to the phone-number-matched recipient",
                    ],
                    "final_state_kind": "new_transactions",
                    "semantic_loss": ["transaction visibility is not represented"],
                },
            )
        )
    return specs


def _roommate_both_directions_spec() -> AppWorldMigrationSpec:
    return AppWorldMigrationSpec(
        scenario_id="cross_app::appworld_d0b1f43_roommate_both_directions",
        source_task_id="d0b1f43_3",
        source_dataset="train",
        generator_id="d0b1f43",
        source_apps=("phone", "venmo"),
        target_domains=("slack", "banking"),
        migration_quality="identity_adapter",
        prompt=(
            "I'm Alice. Read the #home channel membership and bank-account "
            "messages. Treat the other members as my roommates. What is the total value "
            "of all bank transactions with their accounts in either direction "
            "since 2024-03-01? Reply with only the total and don't send "
            "anything or change any data."
        ),
        description=(
            "AppWorld d0b1f43_3: Slack membership replaces Phone relationships and "
            "IBANs stated in Slack replace Venmo identities. The aggregation keeps "
            "both sent and received transactions."
        ),
        steps=(
            _step(
                "read_home_membership",
                "slack",
                "get_users_in_channel",
                "Identify Alice's roommates.",
                arguments={"channel": "home"},
                produces=("home_members",),
            ),
            _step(
                "read_roommate_accounts",
                "slack",
                "read_channel_messages",
                "Map roommates to their stated bank accounts.",
                arguments={"channel": "home"},
                depends_on=("read_home_membership",),
                consumes=("home_members",),
                produces=("roommate_accounts",),
            ),
            _step(
                "sum_both_directions",
                "banking",
                "get_most_recent_transactions",
                "Sum eligible transactions in either direction after the cutoff.",
                arguments={"n": 100},
                depends_on=("read_home_membership", "read_roommate_accounts"),
                consumes=("home_members", "roommate_accounts"),
                produces=("both_directions_total",),
            ),
        ),
        fixtures={
            "slack": {
                "current_user": "Alice",
                "ensure_channels": ["home"],
                "user_channel_memberships": {
                    "Alice": ["home"],
                    "Bob": ["home"],
                    "Charlie": ["home"],
                    "David": ["home"],
                },
                "append_channel_messages": [
                    _channel_message(
                        "Bob",
                        "home",
                        "My bank account for shared expenses is GB29NWBK60161331926819.",
                    ),
                    _channel_message(
                        "Charlie",
                        "home",
                        "My bank account is CH9300762011623852957.",
                    ),
                    _channel_message(
                        "David",
                        "home",
                        "My bank account is SE3550000000054910000003.",
                    ),
                ],
            },
            "banking": {
                "append_transactions": [
                    _transaction(
                        "appworld_d0b1f43_3_old",
                        301,
                        "me",
                        "GB29NWBK60161331926819",
                        650.0,
                        "February shared expense",
                        "2024-02-20",
                    ),
                    _transaction(
                        "appworld_d0b1f43_3_sent_bob",
                        302,
                        "me",
                        "GB29NWBK60161331926819",
                        500.0,
                        "March rent share",
                        "2024-03-05",
                    ),
                    _transaction(
                        "appworld_d0b1f43_3_received_bob",
                        303,
                        "GB29NWBK60161331926819",
                        "me",
                        200.0,
                        "March utility reimbursement",
                        "2024-03-08",
                    ),
                    _transaction(
                        "appworld_d0b1f43_3_sent_charlie",
                        304,
                        "me",
                        "CH9300762011623852957",
                        300.0,
                        "March groceries",
                        "2024-03-10",
                    ),
                    _transaction(
                        "appworld_d0b1f43_3_received_charlie",
                        305,
                        "CH9300762011623852957",
                        "me",
                        100.0,
                        "March dinner share",
                        "2024-03-12",
                    ),
                    _transaction(
                        "appworld_d0b1f43_3_sent_david",
                        306,
                        "me",
                        "SE3550000000054910000003",
                        113.0,
                        "March internet share",
                        "2024-03-15",
                    ),
                    _transaction(
                        "appworld_d0b1f43_3_non_roommate",
                        307,
                        "me",
                        "DE89370400440532013000",
                        900.0,
                        "Not a roommate",
                        "2024-03-20",
                    ),
                    _transaction(
                        "appworld_d0b1f43_3_before_cutoff",
                        308,
                        "CH9300762011623852957",
                        "me",
                        400.0,
                        "February dinner share",
                        "2024-02-28",
                    ),
                ]
            },
        },
        evaluation={
            "allowed_changes": [],
            "requirements": [
                {
                    "kind": "answer_number",
                    "name": "roommate both-directions total",
                    "value": 1213.0,
                    "tolerance": 0.01,
                    "require_single_numeric": False,
                }
            ],
        },
        semantic_changes=(
            "Phone roommate relationships are replaced by Slack #home membership.",
            "Venmo identities are replaced by IBANs stated in Slack.",
            "The fixture values are reseeded while preserving the both-direction aggregation semantics.",
        ),
        source_api_evidence=(
            "phone.search_contacts",
            "venmo.show_transactions",
        ),
        evaluator_contract={
            "source_requirements": [
                "aggregate both sent and received transactions after the month cutoff",
                "include only roommate accounts",
                "make no model changes",
            ],
            "final_state_kind": "answer_number",
        },
    )


def _bill_split_specs() -> list[AppWorldMigrationSpec]:
    configurations = (
        (
            "2",
            "internet",
            "April 2024 Internet Bill.txt",
            184,
            46,
            "Please each pay $46 for the April 2024 internet bill.",
            "2024-05-18",
        ),
        (
            "3",
            "cable",
            "April 2024 Cable Bill.txt",
            128,
            32,
            "Please each pay $32 for the April 2024 cable bill.",
            "2024-05-19",
        ),
    )
    specs: list[AppWorldMigrationSpec] = []
    for index, (
        suffix,
        bill_type,
        filename,
        total,
        share,
        message,
        date,
    ) in enumerate(configurations, start=2):
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=f"cross_app::appworld_3c13f5a_{bill_type}_split",
                source_task_id=f"3c13f5a_{suffix}",
                source_dataset="train",
                generator_id="3c13f5a",
                source_apps=("file_system", "phone", "venmo"),
                target_domains=("workspace", "slack"),
                migration_quality="messaging_primitive_rewrite",
                prompt=(
                    f"I'm Alice. Read the April 2024 {bill_type} bill from my "
                    "cloud drive and the #home channel membership. Split the bill equally "
                    "among everyone in #home, including me. Post one message in "
                    "#home in the form 'Please each pay $<share> for the April "
                    f"2024 {bill_type} bill.' Don't change any other data."
                ),
                description=(
                    f"AppWorld 3c13f5a_{suffix}: the filesystem receipt becomes a "
                    "Workspace file, Phone relationships become Slack membership, and "
                    "Venmo payment requests become one explicit Slack group request."
                ),
                steps=(
                    _step(
                        "read_bill",
                        "workspace",
                        "search_files_by_filename",
                        f"Read the April {bill_type} bill amount.",
                        arguments={"filename": filename},
                        produces=("bill_total",),
                    ),
                    _step(
                        "read_home_members",
                        "slack",
                        "get_users_in_channel",
                        "Identify every bill participant.",
                        arguments={"channel": "home"},
                        produces=("home_members",),
                    ),
                    _step(
                        "request_equal_shares",
                        "slack",
                        "send_channel_message",
                        "Request one equal share from the home channel.",
                        arguments={"channel": "home", "body": message},
                        depends_on=("read_bill", "read_home_members"),
                        consumes=("bill_total", "home_members"),
                        produces=("share_request",),
                    ),
                ),
                fixtures={
                    "workspace": {
                        "append_files": [
                            _file(
                                f"appworld_3c13f5a_{bill_type}_bill",
                                str(95100 + index),
                                filename,
                                (f"{bill_type.title()} Bill - April 2024\nTotal Amount => ${total}\n"),
                                f"{date}T09:00:00",
                            ),
                            _file(
                                f"appworld_3c13f5a_{bill_type}_old_bill",
                                str(95110 + index),
                                f"March 2024 {bill_type.title()} Bill.txt",
                                (f"{bill_type.title()} Bill - March 2024\nTotal Amount => $80\n"),
                                "2024-04-02T09:00:00",
                            ),
                        ]
                    },
                    "slack": {
                        "current_user": "Alice",
                        "ensure_channels": ["home"],
                        "user_channel_memberships": {
                            "Alice": ["home"],
                            "Bob": ["home"],
                            "Charlie": ["home"],
                            "David": ["home"],
                        },
                    },
                },
                evaluation={
                    "allowed_changes": ["slack.channel_inbox"],
                    "requirements": [
                        {
                            "kind": "new_channel_messages",
                            "name": f"one exact {bill_type} share request",
                            "messages": [{"recipient": "home", "body": message}],
                        }
                    ],
                },
                semantic_changes=(
                    "The filesystem bill is represented as a Workspace cloud-drive file.",
                    "Phone roommate relationships are replaced by Slack #home membership.",
                    "Venmo payment requests are rewritten as one explicit Slack group request.",
                ),
                source_api_evidence=(
                    "file_system.read_file",
                    "phone.search_contacts",
                    "venmo.create_payment_request",
                ),
                evaluator_contract={
                    "source_requirements": [
                        f"request the equal share of ${share} from each roommate",
                        "one request per roommate with the original note",
                    ],
                    "target_requirement_kind": "new_channel_messages",
                    "semantic_loss": ["payment-request approval state is not represented by Slack messaging"],
                },
            )
        )
    return specs


def _dinner_split_specs() -> list[AppWorldMigrationSpec]:
    configurations = (
        {
            "suffix": "1",
            "channel": "work",
            "subject": "Work Dinner",
            "note_title": "Work Dinner Expense Shares at Silver Lining Cafe",
            "participants": {
                "Kayla": (20, "GB29NWBK60161331926819"),
                "Sandra": (19, "CH9300762011623852957"),
                "Stephen": (20, "SE3550000000054910000003"),
                "Jamie": (15, "DE89370400440532013000"),
                "Anita": (23, "FR1420041010050500013M02606"),
                "Travis": (39, "BE68539007547034"),
                "Sabrina": (39, "NL91ABNA0417164300"),
            },
            "already_paid": ("Kayla", "Jamie", "Anita", "Sabrina"),
            "pending": ("Sandra", "Stephen", "Travis"),
            "date": "2024-05-19",
        },
        {
            "suffix": "2",
            "channel": "friends",
            "subject": "Friends Dinner",
            "note_title": "Friends Dinner Expense Shares at Spice Symphony Kitchen",
            "participants": {
                "Adrian": (36, "GB29NWBK60161331926819"),
                "Katie": (30, "CH9300762011623852957"),
                "Martin": (35, "SE3550000000054910000003"),
                "Robin": (36, "DE89370400440532013000"),
                "Matthew": (19, "FR1420041010050500013M02606"),
                "Melissa": (31, "BE68539007547034"),
                "Glenn": (32, "NL91ABNA0417164300"),
                "Brenda": (40, "DK5000400440116243"),
            },
            "already_paid": ("Robin", "Matthew", "Glenn", "Brenda"),
            "pending": ("Adrian", "Katie", "Martin", "Melissa"),
            "date": "2024-05-20",
        },
        {
            "suffix": "3",
            "channel": "work",
            "subject": "Dinner with Colleagues",
            "note_title": "Work Dinner Expense Shares at Velvet and Vine Dining",
            "participants": {
                "Stephen": (33, "GB29NWBK60161331926819"),
                "Sabrina": (32, "CH9300762011623852957"),
                "Jamie": (31, "SE3550000000054910000003"),
                "Allison": (26, "DE89370400440532013000"),
                "Stacy": (28, "FR1420041010050500013M02606"),
                "Travis": (21, "BE68539007547034"),
                "Kristin": (38, "NL91ABNA0417164300"),
                "Anita": (32, "DK5000400440116243"),
                "Kayla": (16, "NO9386011117947"),
            },
            "already_paid": ("Allison", "Stacy", "Travis", "Kristin", "Kayla"),
            "pending": ("Stephen", "Sabrina", "Jamie", "Anita"),
            "date": "2024-05-21",
        },
    )
    specs: list[AppWorldMigrationSpec] = []
    for index, config in enumerate(configurations, start=1):
        suffix = str(config["suffix"])
        subject = str(config["subject"])
        channel = str(config["channel"])
        participants = dict(config["participants"])
        pending = tuple(config["pending"])
        already_paid = tuple(config["already_paid"])
        note_lines = [
            f"# {subject}",
            *[f"- {name} => ${amount}" for name, (amount, _iban) in participants.items()],
        ]
        pending_request_lines = [f"{name} ${participants[name][0]}" for name in pending]
        request_body = f"{subject} unpaid shares: " + "; ".join(pending_request_lines) + ". Please pay your share."
        steps = [
            _step(
                "read_expense_note",
                "workspace",
                "search_files_by_filename",
                "Read the current dinner expense note.",
                arguments={"filename": str(config["note_title"])},
                produces=("expense_note", "participant_shares"),
            ),
            _step(
                "read_account_mapping",
                "slack",
                "read_channel_messages",
                "Read member identities and their stated bank accounts.",
                arguments={"channel": channel},
                produces=("account_mapping",),
            ),
            _step(
                "read_channel_members",
                "slack",
                "get_users_in_channel",
                "Read the channel member list.",
                arguments={"channel": channel},
                produces=("channel_members",),
            ),
            _step(
                "read_received_payments",
                "banking",
                "get_most_recent_transactions",
                "Identify participants who have already paid.",
                arguments={"n": 100},
                depends_on=("read_expense_note", "read_account_mapping"),
                consumes=("participant_shares", "account_mapping"),
                produces=("paid_participants",),
            ),
        ]
        steps.append(
            _step(
                "post_unpaid_share_requests",
                "slack",
                "send_channel_message",
                "Post one exact request listing every unpaid share.",
                arguments={"channel": channel, "body": request_body},
                depends_on=(
                    "read_expense_note",
                    "read_channel_members",
                    "read_account_mapping",
                    "read_received_payments",
                ),
                consumes=(
                    "participant_shares",
                    "channel_members",
                    "paid_participants",
                ),
                produces=("share_request_message",),
            )
        )
        fixtures = {
            "workspace": {
                "append_files": [
                    _file(
                        f"appworld_22cc237_{suffix}_current_note",
                        str(95200 + index),
                        f"{config['note_title']}.txt",
                        "\n".join(note_lines) + "\n",
                        f"{config['date']}T09:00:00",
                    ),
                    _file(
                        f"appworld_22cc237_{suffix}_old_note",
                        str(95210 + index),
                        f"Previous {subject} Expense Shares.txt",
                        "# Previous dinner\n- Example => $99\n",
                        "2024-04-17T09:00:00",
                    ),
                ]
            },
            "slack": {
                "current_user": "Alice",
                "ensure_channels": [channel],
                "user_channel_memberships": {
                    "Alice": [channel],
                    **{name: [channel] for name in participants},
                },
                "append_channel_messages": [
                    _channel_message(
                        name,
                        channel,
                        f"My bank account is {iban}.",
                    )
                    for name, (_amount, iban) in participants.items()
                ],
            },
            "banking": {
                "append_transactions": [
                    _transaction(
                        f"appworld_22cc237_{suffix}_{name.lower()}_paid",
                        400 + index * 20 + paid_index,
                        participants[name][1],
                        "me",
                        float(participants[name][0]),
                        subject,
                        str(config["date"]),
                    )
                    for paid_index, name in enumerate(already_paid, start=1)
                ]
            },
        }
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=f"cross_app::appworld_22cc237_dinner_split_{suffix}",
                source_task_id=f"22cc237_{suffix}",
                source_dataset="train",
                generator_id="22cc237",
                source_apps=("phone", "simple_note", "venmo"),
                target_domains=("workspace", "slack", "banking"),
                migration_quality="messaging_primitive_rewrite",
                prompt=(
                    "I'm Alice. Read the current dinner expense note. In Slack's "
                    f"#{channel} channel, get the member list and read the "
                    "bank-account messages. Consider a participant "
                    f"paid if they sent me a bank transfer titled '{subject}'. "
                    f"Post one message in #{channel} exactly as '{subject} unpaid "
                    "shares: <name> $<amount>; <name> $<amount>. Please pay your "
                    "share.' List every unpaid participant once and don't change "
                    "other data."
                ),
                description=(
                    f"AppWorld 22cc237_{suffix}: Phone relationships become Slack "
                    "membership, Simple Note becomes a Workspace file, received Venmo "
                    "payments become Banking transactions, and Venmo payment requests "
                    "become Slack direct requests."
                ),
                steps=tuple(steps),
                fixtures=fixtures,
                evaluation={
                    "allowed_changes": ["slack.channel_inbox"],
                    "requirements": [
                        {
                            "kind": "new_channel_messages",
                            "name": "one exact request for all unpaid participants",
                            "messages": [{"recipient": channel, "body": request_body}],
                        }
                    ],
                },
                semantic_changes=(
                    "Phone relationship lookup is represented by Slack member messages.",
                    "Simple Note expense data is represented as a Workspace cloud-drive note.",
                    "Received Venmo transactions are represented as Banking transactions.",
                    "Venmo payment requests are represented as one explicit Slack channel request that lists every unpaid share.",
                ),
                source_api_evidence=(
                    "phone.search_contacts",
                    "simple_note.search_notes",
                    "simple_note.show_note",
                    "venmo.show_transactions",
                    "venmo.create_payment_request",
                ),
                evaluator_contract={
                    "source_requirements": [
                        "match each participant to their note amount",
                        "exclude participants with a matching received transaction",
                        "create one payment request for every remaining participant",
                    ],
                    "target_requirement_kind": "new_channel_messages",
                    "semantic_loss": [
                        "Venmo individual request approval state is not represented in Slack",
                        "per-request recipient objects are collapsed into one group message",
                    ],
                },
            )
        )
    return specs


def _refund_specs() -> list[AppWorldMigrationSpec]:
    configurations = (
        ("1", "Robert", 74.0, "2024-05-20"),
        ("2", "Cory", 48.0, "2024-05-21"),
        ("3", "Brandon", 56.0, "2024-05-22"),
    )
    accounts = (
        "GB29NWBK60161331926819",
        "CH9300762011623852957",
        "SE3550000000054910000003",
    )
    specs: list[AppWorldMigrationSpec] = []
    for index, (suffix, person, amount, date) in enumerate(configurations):
        iban = accounts[index]
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=f"cross_app::appworld_60d0b5b_refund_{suffix}",
                source_task_id=f"60d0b5b_{suffix}",
                source_dataset="train",
                generator_id="60d0b5b",
                source_apps=("phone", "venmo"),
                target_domains=("slack", "banking"),
                migration_quality="identity_adapter",
                prompt=(
                    f"Read {person}'s Slack messages to Alice. They give their "
                    "bank account and latest approved payment request. Refund "
                    f"that exact amount immediately as a normal transaction "
                    f"dated {date}, with the subject 'Returning the accidental "
                    "payment'. Do not schedule it, and make only that transfer."
                ),
                description=(
                    f"AppWorld 60d0b5b_{suffix}: the Phone contact becomes a Slack "
                    "sender and the latest approved Venmo request amount becomes "
                    "structured evidence for one Banking refund."
                ),
                steps=(
                    _step(
                        "read_latest_approved_request",
                        "slack",
                        "read_inbox",
                        "Find the recipient account and latest approved request amount.",
                        arguments={"user": "Alice"},
                        produces=("refund_recipient", "refund_iban", "refund_amount"),
                    ),
                    _step(
                        "send_accidental_refund",
                        "banking",
                        "send_money",
                        "Refund the latest approved request exactly once.",
                        arguments={
                            "recipient": iban,
                            "amount": amount,
                            "subject": "Returning the accidental payment",
                            "date": date,
                        },
                        depends_on=("read_latest_approved_request",),
                        consumes=("refund_recipient", "refund_iban", "refund_amount"),
                        produces=("refund_transaction",),
                    ),
                ),
                fixtures={
                    "slack": {
                        "current_user": "Alice",
                        "ensure_users": [person],
                        "append_direct_messages": [
                            _dm(person, f"My bank account is {iban}."),
                            _dm(
                                person,
                                f"My latest approved payment request is for ${amount:.2f} on {date}.",
                            ),
                            _dm(
                                "Charlie",
                                "I approved your earlier payment request for $31.00 on 2024-04-10.",
                            ),
                        ],
                    }
                },
                evaluation={
                    "allowed_changes": ["banking.bank_account.transactions"],
                    "requirements": [
                        {
                            "kind": "new_transactions",
                            "name": "one exact accidental-payment refund",
                            "transactions": [
                                {
                                    "recipient": iban,
                                    "amount": amount,
                                    "subject": "Returning the accidental payment",
                                }
                            ],
                        }
                    ],
                },
                semantic_changes=(
                    "Phone contact lookup is represented by a Slack sender.",
                    "The target's latest approved Venmo request is represented by one explicit Slack request message; an earlier request from another sender is retained as a distractor.",
                    "Venmo transaction and balance mutations are represented by one Banking transaction.",
                ),
                source_api_evidence=(
                    "phone.search_contacts",
                    "venmo.show_sent_payment_requests",
                    "venmo.create_transaction",
                ),
                evaluator_contract={
                    "source_requirements": [
                        "one added transaction",
                        "exact recipient",
                        "exact latest approved request amount",
                        "no updated or removed transactions",
                    ],
                    "final_state_kind": "new_transactions",
                    "semantic_loss": ["Venmo notification and balance fields are represented by Banking state"],
                },
            )
        )
    return specs


def _restaurant_total_specs() -> list[AppWorldMigrationSpec]:
    configurations = (
        (
            "1",
            "Dinner",
            "Azure Harbor Bistro",
            38,
            227,
            (
                ("Jordan", 29.0),
                ("Angela", 20.0),
                ("Adam", 42.0),
                ("Jeffrey", 44.0),
                ("Connor", 23.0),
                ("Glenn", 31.0),
            ),
            "2024-05-18",
        ),
        (
            "2",
            "Lunch",
            "Enchanted Eats",
            20,
            396,
            (
                ("Stephen", 25.0),
                ("Kristin", 40.0),
                ("Allison", 47.0),
                ("Cody", 42.0),
                ("Travis", 30.0),
                ("Grant", 49.0),
                ("Stacy", 43.0),
                ("Sabrina", 38.0),
                ("Sandra", 31.0),
                ("Kayla", 31.0),
            ),
            "2024-05-19",
        ),
        (
            "3",
            "Dinner",
            "Whimsical Bites",
            34,
            275,
            (
                ("Angela", 26.0),
                ("Adam", 39.0),
                ("Jeffrey", 47.0),
                ("Ashlee", 40.0),
                ("Connor", 40.0),
                ("Glenn", 49.0),
            ),
            "2024-05-20",
        ),
    )
    specs: list[AppWorldMigrationSpec] = []
    for index, (
        suffix,
        meal,
        restaurant,
        my_share,
        expected_total,
        payments,
        date,
    ) in enumerate(configurations, start=1):
        note_lines = [
            f"Manager reimbursement ledger - {restaurant}",
            f"Alice's {meal.lower()} share: ${my_share}",
            "",
            *[f"- {name} paid ${amount:.0f} to the manager for {restaurant}" for name, amount in payments],
        ]
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=f"cross_app::appworld_383cbac_restaurant_total_{suffix}",
                source_task_id=f"383cbac_{suffix}",
                source_dataset="train",
                generator_id="383cbac",
                source_apps=("phone", "venmo"),
                target_domains=("slack", "workspace"),
                migration_quality="storage_adapter",
                prompt=(
                    "I'm Alice. My manager paid for a work meal. Read the #work "
                    "role message to identify the manager and restaurant, then "
                    "open that restaurant's reimbursement ledger in my cloud "
                    "drive. Add my own share once to the combined total of all "
                    "coworker payments to the manager, then tell me the total. "
                    "Don't send messages or change any data."
                ),
                description=(
                    f"AppWorld 383cbac_{suffix}: Phone relationships become Slack #work "
                    "role-message evidence. The Venmo social-feed transactions "
                    "between coworkers and the manager are preserved as a read-only "
                    "Workspace reimbursement ledger because Banking exposes only Alice's "
                    "own account."
                ),
                steps=(
                    _step(
                        "read_manager_identity",
                        "slack",
                        "read_channel_messages",
                        "Identify the manager and restaurant context.",
                        arguments={"channel": "work"},
                        produces=("manager_identity", "restaurant_context"),
                    ),
                    _step(
                        "read_reimbursement_ledger",
                        "workspace",
                        "search_files_by_filename",
                        "Read coworker payments recorded from the manager's social feed.",
                        arguments={"filename": f"{restaurant} Ledger.txt"},
                        depends_on=("read_manager_identity",),
                        consumes=("manager_identity", "restaurant_context"),
                        produces=("reimbursement_entries", "manager_total"),
                    ),
                ),
                fixtures={
                    "slack": {
                        "current_user": "Alice",
                        "ensure_channels": ["work"],
                        "user_channel_memberships": {
                            "Alice": ["work"],
                            "Manager Spencer": ["work"],
                            **{name: ["work"] for name, _amount in payments},
                        },
                        "append_channel_messages": [
                            _channel_message(
                                "Manager Spencer",
                                "work",
                                f"I paid for our {meal.lower()} at {restaurant}. "
                                "Reimbursements are in the shared ledger.",
                            )
                        ],
                    },
                    "workspace": {
                        "append_files": [
                            _file(
                                f"appworld_383cbac_{suffix}_ledger",
                                str(95300 + index),
                                f"{restaurant} Ledger.txt",
                                "\n".join(note_lines) + "\n",
                                f"{date}T20:00:00",
                            ),
                            _file(
                                f"appworld_383cbac_{suffix}_distractor",
                                str(95310 + index),
                                "Other Restaurant Ledger.txt",
                                "Manager reimbursement ledger - Other Restaurant\n- Example paid $999 to the manager\n",
                                "2024-04-01T20:00:00",
                            ),
                        ]
                    },
                },
                evaluation={
                    "allowed_changes": [],
                    "requirements": [
                        {
                            "kind": "answer_number",
                            "name": "manager restaurant total",
                            "value": float(expected_total),
                            "tolerance": 0.01,
                            "require_single_numeric": False,
                        }
                    ],
                },
                semantic_changes=(
                    "Phone coworker relationships are preserved by the Slack #work role message.",
                    "Venmo social-feed transactions are represented by a read-only Workspace reimbursement ledger.",
                ),
                source_api_evidence=(
                    "phone.search_contacts",
                    "venmo.show_social_feed",
                ),
                evaluator_contract={
                    "source_requirements": [
                        "sum the current user's share and matching coworker payments",
                        "exclude unrelated social-feed entries",
                        "make no model changes",
                    ],
                    "final_state_kind": "answer_number",
                    "semantic_loss": ["third-party transaction visibility is represented as a read-only ledger"],
                },
            )
        )
    return specs


def _dinner_recipe_specs() -> list[AppWorldMigrationSpec]:
    """Migrate supported test-normal Phone + Simple Note instances."""
    configurations = (
        (
            "1",
            "Joyce Weaver",
            "Thai Red Curry with Tofu",
            (
                "Caprese Salad with Balsamic Glaze",
                "Mediterranean Quinoa Salad",
                "Classic Spaghetti Carbonara",
                "Vegetable Stir-Fry with Tofu",
            ),
            "2023-05-18T12:00:00",
        ),
        (
            "2",
            "Isaac Miller",
            "Homestyle Chicken Noodle Soup",
            (
                "Thai Red Curry with Tofu",
                "Honey Mustard Glazed Salmon",
                "Baked Lemon Herb Salmon",
                "Caprese Salad with Balsamic Glaze",
            ),
            "2023-05-18T12:00:00",
        ),
        (
            "3",
            "Angelica Wilson",
            "Mediterranean Quinoa Salad",
            (
                "Vegetable Stir-Fry with Tofu",
                "Baked Lemon Herb Salmon",
                "Spinach and Mushroom Stuffed Chicken",
            ),
            "2023-05-18T12:00:00",
        ),
    )
    specs = []
    for index, (suffix, requester, favorite, others, last_modified) in enumerate(
        configurations,
        start=1,
    ):
        recipe_lines = [f"{favorite} [favorite: true]"]
        recipe_lines.extend(f"{name} [favorite: false]" for name in others)
        source = _source(
            f"ffe6d5e_{suffix}",
            "ffe6d5e",
            ("phone", "simple_note"),
            ("slack", "workspace"),
            dataset="test_normal",
            quality="storage_adapter",
            changes=(
                "Phone text messages are represented as Slack direct messages.",
                "The Simple Note recipe note is represented as a Workspace text file.",
            ),
            evidence=(
                "phone.search_text_messages",
                "simple_note.search_notes",
                "simple_note.show_note",
                "phone.send_text_message",
            ),
            evaluator={
                "source_requirements": [
                    "one reply to the requesting relative",
                    "reply contains exactly one favorite recipe name",
                    "reply contains no non-favorite recipe name",
                ],
                "final_state_kind": "new_direct_messages",
            },
        )
        specs.append(
            AppWorldMigrationSpec(
                scenario_id=(f"cross_app::appworld_ffe6d5e_dinner_choice_{suffix}"),
                source_task_id=source["source_task_id"],
                source_dataset=source["source_dataset"],
                generator_id=source["generator_id"],
                source_apps=source["source_apps"],
                target_domains=source["target_domains"],
                migration_quality=source["quality"],
                prompt=(
                    "Read the latest dinner question in Alice's Slack inbox. "
                    "Reply to the sender using the exact Slack display name "
                    "shown on that message, with just the recipe marked "
                    "favorite in 'Favorite Recipes.txt' in my cloud drive. An "
                    "email address or shared channel membership is not needed."
                ),
                description=(
                    f"AppWorld held-out test_normal task ffe6d5e_{suffix}: "
                    "Phone and Simple Note are adapted to Slack and Workspace. "
                    "The source allows any favorite recipe; this migration "
                    "uses the single favorite present in the adapted note."
                ),
                steps=(
                    _step(
                        "read_dinner_request",
                        "slack",
                        "read_inbox",
                        f"Read {requester}'s dinner request.",
                        arguments={"user": "Alice"},
                        produces=("requester", "dinner_request"),
                    ),
                    _step(
                        "read_favorite_recipe",
                        "workspace",
                        "search_files_by_filename",
                        "Read the favorite recipe note.",
                        arguments={"filename": "Favorite Recipes.txt"},
                        depends_on=("read_dinner_request",),
                        consumes=("dinner_request",),
                        produces=("favorite_recipe",),
                    ),
                    _step(
                        "reply_with_favorite_recipe",
                        "slack",
                        "send_direct_message",
                        "Reply with exactly one favorite recipe name.",
                        arguments={"recipient": requester, "body": favorite},
                        depends_on=(
                            "read_dinner_request",
                            "read_favorite_recipe",
                        ),
                        consumes=("requester", "favorite_recipe"),
                        produces=("dinner_reply",),
                    ),
                ),
                fixtures={
                    "slack": {
                        "current_user": "Alice",
                        "ensure_users": [requester],
                        "append_direct_messages": [
                            {
                                "sender": requester,
                                "recipient": "Alice",
                                "body": ("I'll cook tonight. What would you like for dinner?"),
                            }
                        ],
                    },
                    "workspace": {
                        "append_files": [
                            _file(
                                f"appworld_ffe6d5e_{suffix}_recipes",
                                str(95400 + index),
                                "Favorite Recipes.txt",
                                "\n".join(recipe_lines) + "\n",
                                last_modified,
                            )
                        ]
                    },
                },
                evaluation={
                    "allowed_changes": ["slack.user_inbox"],
                    "requirements": [
                        {
                            "kind": "new_direct_messages",
                            "name": "one exact favorite recipe reply",
                            "messages": [
                                {
                                    "recipient": requester,
                                    "body": favorite,
                                }
                            ],
                        }
                    ],
                },
                semantic_changes=(
                    "Phone text messages become Slack direct messages.",
                    "The Simple Note recipe collection becomes one Workspace text file.",
                    "One source-allowed favorite is chosen deterministically for exact evaluation.",
                ),
                source_api_evidence=source["evidence"],
                evaluator_contract=source["evaluator"],
            )
        )
    return specs


def get_appworld_migration_specs() -> tuple[AppWorldMigrationSpec, ...]:
    """Return the reviewed first-batch migration specifications."""
    specs = (
        _movie_specs()
        + _grocery_specs()
        + _identity_payment_specs()
        + [_roommate_both_directions_spec()]
        + _bill_split_specs()
        + _dinner_split_specs()
        + _refund_specs()
        + _restaurant_total_specs()
        + _dinner_recipe_specs()
    )
    scenario_ids = [spec.scenario_id for spec in specs]
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("Duplicate AppWorld migration scenario IDs.")
    for spec in specs:
        spec.validate()
    return tuple(specs)


# Conservative family-level disposition for all 39 inventory candidates.
# The five excluded families require Venmo social actions with no four-domain
# equivalent.  They remain in the inventory but must not enter migration metrics.
GENERATOR_MIGRATION_DISPOSITIONS: dict[str, dict[str, Any]] = {
    "22cc237": {
        "status": "migrated_with_rewrite",
        "instances": 3,
        "reason": "Payment requests are represented as Slack direct messages.",
    },
    "29caf6f": {
        "status": "migrated",
        "instances": 3,
        "reason": "Phone and Simple Note map to Slack and Workspace.",
    },
    "2a163ab": {
        "status": "excluded",
        "instances": 3,
        "reason": "Venmo social-feed likes have no supported APP primitive.",
    },
    "37a8675": {
        "status": "migrated_with_rewrite",
        "instances": 3,
        "reason": "Phone identity resolution maps to Slack evidence and Banking IBAN payment.",
    },
    "383cbac": {
        "status": "migrated_with_rewrite",
        "instances": 3,
        "reason": "Third-party social transactions map to a read-only Workspace ledger.",
    },
    "3c13f5a": {
        "status": "migrated_with_rewrite",
        "instances": 3,
        "reason": "Payment requests become Slack requests while bill and membership evidence are preserved.",
    },
    "4fab96f": {
        "status": "excluded",
        "instances": 3,
        "reason": "Unanswered Venmo request reminders have no supported APP primitive.",
    },
    "530b157": {
        "status": "migrated_with_rewrite",
        "instances": 3,
        "reason": "Phone messages and Venmo transfer map to Slack and Banking.",
    },
    "60d0b5b": {
        "status": "migrated_with_rewrite",
        "instances": 3,
        "reason": "Approved-request evidence maps to dated Slack messages and one Banking refund.",
    },
    "6ea6792": {
        "status": "excluded",
        "instances": 3,
        "reason": "Venmo payment-request approval has no supported APP primitive.",
    },
    "afc0fce": {
        "status": "excluded",
        "instances": 3,
        "reason": "Venmo comments and likes have no supported APP primitive.",
    },
    "d0b1f43": {
        "status": "migrated_with_rewrite",
        "instances": 3,
        "reason": "Contact relationships map to Slack membership and Venmo identities to stated IBANs.",
    },
    "df61dc5": {
        "status": "excluded",
        "instances": 3,
        "reason": "Venmo social-feed likes have no supported APP primitive.",
    },
}


def migration_disposition_summary() -> dict[str, int]:
    summary = {
        "source_candidates": 0,
        "migrated_source_instances": 0,
        "excluded_source_instances": 0,
    }
    for disposition in GENERATOR_MIGRATION_DISPOSITIONS.values():
        count = int(disposition["instances"])
        summary["source_candidates"] += count
        key = "excluded_source_instances" if disposition["status"] == "excluded" else "migrated_source_instances"
        summary[key] += count
    return summary
