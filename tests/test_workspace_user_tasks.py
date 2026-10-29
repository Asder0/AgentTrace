import datetime
from copy import deepcopy

import pytest

from agentdojo.task_suite.load_suites import get_suite  # isort: skip  -- avoid circular import issue
from agentdojo.default_suites.v1.tools.email_client import Inbox
from agentdojo.default_suites.v1.tools.types import (
    CalendarEvent,
    CloudDriveFile,
    Email,
    EmailID,
)
from agentdojo.default_suites.v1.workspace.task_suite import WorkspaceEnvironment
from agentdojo.default_suites.v1.workspace.user_tasks import check_only_unread_emails_marked_as_read


@pytest.fixture
def pre_env() -> WorkspaceEnvironment:
    suite = get_suite("v1.2.2", "workspace")
    workspace_env = suite.load_and_inject_default_environment({})
    assert isinstance(workspace_env, WorkspaceEnvironment)
    return workspace_env


def test_check_only_unread_emails_marked_as_read_no_changes(pre_env: WorkspaceEnvironment):
    """Test that the check passes when there are no changes to the environment."""

    post_env = deepcopy(pre_env)

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is True


def test_email_entity_ids_must_be_numeric():
    with pytest.raises(ValueError, match="numeric strings"):
        Email(
            id_=EmailID("scenario_custom_fixture"),
            sender="carol@example.com",
            recipients=["bob@example.com"],
            subject="Opaque ID",
            body="Imported fixture.",
        )

    email = Email(
        id_=EmailID("7"),
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Numeric ID",
        body="Numeric fixture.",
    )
    inbox = Inbox(
        account_email="bob@example.com",
        initial_emails=[email],
    )

    assert inbox._get_next_id() == EmailID("8")


def test_calendar_and_file_entity_ids_must_be_numeric():
    with pytest.raises(ValueError, match="numeric strings"):
        CalendarEvent(
            id_="scenario_event",
            title="Invalid event",
            description="Invalid fixture.",
            start_time=datetime.datetime(2024, 6, 10, 9),
            end_time=datetime.datetime(2024, 6, 10, 10),
            location="Paris",
            participants=["alice@example.com"],
        )
    with pytest.raises(ValueError, match="numeric strings"):
        CloudDriveFile(
            id_="scenario_file",
            filename="invalid.txt",
            content="Invalid fixture.",
            owner="alice@example.com",
            last_modified=datetime.datetime(2024, 6, 10, 9),
        )


def test_check_only_unread_emails_marked_as_read_only_read_field_changed(pre_env: WorkspaceEnvironment):
    """Test that the check passes when only the 'read' field of unread emails is changed."""

    post_env = deepcopy(pre_env)

    # Mark all unread emails as read
    unread_count = 0
    for _, email in post_env.inbox.emails.items():
        if not email.read:
            email.read = True
            unread_count += 1

    # Should have at least one unread email in the test environment
    assert unread_count > 0, "Test environment should have unread emails"

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is True


def test_check_only_unread_emails_marked_as_read_partial_read(pre_env: WorkspaceEnvironment):
    """Test that the check passes when only some unread emails are marked as read."""

    post_env = deepcopy(pre_env)

    # Mark only the first unread email as read
    for _, email in post_env.inbox.emails.items():
        if not email.read:
            email.read = True
            break

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is True


def test_check_only_unread_emails_marked_as_read_other_changes(pre_env: WorkspaceEnvironment):
    """Test that the check fails when other fields are changed."""

    post_env = deepcopy(pre_env)

    # Change something other than the read field
    for _, email in post_env.inbox.emails.items():
        email.subject = "Modified Subject"
        break

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is False


def test_check_only_unread_emails_marked_as_read_read_field_and_other_changes(pre_env: WorkspaceEnvironment):
    """Test that the check fails when the read field and other fields are changed."""

    post_env = deepcopy(pre_env)

    # Change both the read field and something else
    for _, email in post_env.inbox.emails.items():
        if not email.read:
            email.read = True
            email.subject = "Modified Subject"
            break

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is False


def test_check_only_unread_emails_marked_as_read_already_read_email_changed(pre_env: WorkspaceEnvironment):
    """Test that the check fails when an already-read email is modified."""

    post_env = deepcopy(pre_env)

    # Find an already-read email and modify it
    found_read_email = False
    for _, email in post_env.inbox.emails.items():
        if email.read:
            email.subject = "Modified Subject"
            found_read_email = True
            break

    # If there are no read emails in the test environment, skip this test
    if not found_read_email:
        # Mark one as read first, then modify it in a second change
        for _, email in pre_env.inbox.emails.items():
            if not email.read:
                email.read = True
                break
        post_env = deepcopy(pre_env)
        for _, email in post_env.inbox.emails.items():
            if email.read:
                email.subject = "Modified Subject"
                break

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is False


def test_check_only_unread_emails_marked_as_read_email_added(pre_env: WorkspaceEnvironment):
    """Test that the check fails when an email is added."""

    post_env = deepcopy(pre_env)

    # Add a new email (simulate by changing the structure)
    new_email = Email(
        id_=EmailID("999"),
        subject="New Email",
        body="This is a new email",
        sender="test@example.com",
        recipients=["recipient@example.com"],
        timestamp=datetime.datetime(2024, 1, 1, 0, 0, 0),
        read=False,
    )
    post_env.inbox.emails[EmailID("999")] = new_email

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is False


def test_check_only_unread_emails_marked_as_read_calendar_changed(pre_env: WorkspaceEnvironment):
    """Test that the check fails when calendar is changed."""

    post_env = deepcopy(pre_env)

    # Modify calendar
    for event_id, event in post_env.calendar.events.items():
        event.title = "Modified Event"
        break

    result = check_only_unread_emails_marked_as_read(pre_env, post_env)
    assert result is False
