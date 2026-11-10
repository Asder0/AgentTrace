"""Shared artifact-to-consumer-parameter semantics for cross-APP tasks."""

from __future__ import annotations

# None means that every consumer parameter is an allowed destination for the
# artifact (for example, a balance can be used in arbitrary reasoning).
ARTIFACT_TARGET_PARAMETERS: dict[str, frozenset[str] | None] = {
    "account_balance": frozenset(),
    "account_mapping": frozenset(),
    "available_budget": frozenset({"body"}),
    "bill_amount": frozenset({"amount"}),
    "bill_total": frozenset({"body"}),
    "bob_iban": frozenset({"recipient"}),
    "bob_identity": frozenset({"recipient"}),
    "car_reservation": frozenset({"body"}),
    "channel_members": frozenset({"body", "recipient"}),
    "city": frozenset({"city"}),
    "calendar_events": frozenset({"body"}),
    "coworker_accounts": frozenset(),
    "created_file": None,
    "current_day": frozenset({"date", "start_time", "start_day"}),
    "dinner_request": frozenset({"body"}),
    "director_constraint": frozenset({"filename"}),
    "favorite_recipe": frozenset({"body"}),
    "flight_constraints": frozenset(
        {"departure_city", "arrival_city"}
    ),
    "flight_options": frozenset({"body"}),
    "friend_iban": frozenset({"recipient"}),
    "friend_identity": frozenset({"recipient"}),
    "fuel_options": frozenset({"company", "company_name"}),
    "grocery_amount": frozenset({"amount"}),
    "home_members": frozenset({"recipient", "body", "n"}),
    "hotel_candidates": frozenset({"hotel", "hotel_names"}),
    "hotel_constraints": frozenset(
        {
            "hotel",
            "hotel_names",
            "start_day",
            "end_day",
        }
    ),
    "hotel_name": frozenset({"hotel", "hotel_names"}),
    "hotel_options": frozenset({"hotel", "hotel_names", "body"}),
    "hotel_price": frozenset({"hotel"}),
    "hotel_prices": frozenset({"hotel_names"}),
    "hotel_ratings": frozenset({"hotel"}),
    "hotel_reservation": frozenset({"body"}),
    "invoice_amount": frozenset({"amount"}),
    "invoice_iban": frozenset({"recipient"}),
    "invoice_payment": frozenset({"body"}),
    "lodging_preference": frozenset(
        {
            "city",
            "hotel",
            "hotel_names",
            "start_day",
            "end_day",
        }
    ),
    "manager_identity": frozenset({"filename"}),
    "matched_contact": frozenset({"recipient"}),
    "matched_iban": frozenset({"recipient"}),
    "matching_movie_titles": frozenset({"body"}),
    "matching_titles": frozenset({"body"}),
    "movie_requester": frozenset({"recipient"}),
    "nightly_budget": frozenset({"amount", "body"}),
    "paid_participants": frozenset({"body"}),
    "payment_notice": frozenset({"body"}),
    "participant_shares": frozenset({"body", "n"}),
    "refund_amount": frozenset({"amount"}),
    "refund_iban": frozenset({"recipient"}),
    "refund_recipient": frozenset({"recipient"}),
    "reimbursement": frozenset({"body"}),
    "reimbursement_transaction": frozenset({"body"}),
    "rental_candidates": frozenset({"company_name"}),
    "rental_constraints": frozenset(
        {
            "city",
            "start_time",
            "end_time",
        }
    ),
    "rental_prices": frozenset({"company", "company_name"}),
    "requested_director": frozenset({"body"}),
    "requester": frozenset({"recipient"}),
    "recipient_account": frozenset({"recipient"}),
    "requester_email": frozenset({"recipient"}),
    "restaurant_candidates": frozenset(
        {"restaurant", "restaurant_names"}
    ),
    "restaurant_constraints": frozenset(
        {
            "restaurant",
            "restaurant_names",
            "start_time",
        }
    ),
    "restaurant_context": frozenset({"filename"}),
    "restaurant_prices": frozenset({"restaurant_names"}),
    "restaurant_ratings": frozenset({"restaurant"}),
    "restaurant_reservation": frozenset({"body"}),
    "roommate_accounts": frozenset(),
    "selected_hotel": frozenset({"hotel", "hotel_names"}),
    "sent_total": frozenset({"body"}),
    "stay_dates": frozenset({"start_day", "end_day"}),
    "slack_channel_list": frozenset({"channel"}),
    "slack_channels": frozenset({"channel"}),
    "target_filename": frozenset(
        {"filename", "file_path", "file_id"}
    ),
    "todo_content": frozenset({"body", "content"}),
    "trip_dates": frozenset(
        {
            "start_day",
            "end_day",
            "start_time",
            "end_time",
            "date",
        }
    ),
    "trip_destination": frozenset(
        {
            "city",
            "departure_city",
            "arrival_city",
            "location",
        }
    ),
    "trip_request": frozenset(
        {
            "body",
            "city",
            "start_day",
            "end_day",
            "hotel",
            "hotel_names",
        }
    ),
    "transaction_question": frozenset({"body"}),
    "value": None,
    "work_members": frozenset({"recipient", "body", "n"}),
}


def resolve_artifact_target_parameters(
    artifact: str,
) -> tuple[bool, frozenset[str] | None]:
    """Return whether an artifact has a declared target scope.

    A known artifact with ``None`` parameters deliberately permits any target
    parameter. An unknown artifact has no declared scope and must be rejected
    by contract validation rather than treated as a wildcard.
    """

    name = str(artifact or "")
    if name not in ARTIFACT_TARGET_PARAMETERS:
        return False, None
    return True, ARTIFACT_TARGET_PARAMETERS[name]
