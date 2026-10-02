from __future__ import annotations

import pytest

from kairoseki.labels import DESTRUCTIVE, PRIVATE, SINK, UNTRUSTED, classify, split_name

# Tool names taken from popular real MCP servers (GitHub, fetch, filesystem, Slack, Gmail, Playwright...)
CASES = [
    ("get_issue", {UNTRUSTED}),
    ("list_issues", {UNTRUSTED}),
    ("get_pull_request", {UNTRUSTED}),
    ("get_file_contents", {PRIVATE}),
    ("read_file", {PRIVATE}),
    ("list_directory", {PRIVATE}),
    ("create_pull_request", {SINK, DESTRUCTIVE}),
    ("add_issue_comment", {SINK, DESTRUCTIVE}),
    ("push_files", {SINK}),
    ("send_email", {SINK}),
    ("slack_post_message", {SINK}),
    ("fetch", {UNTRUSTED, SINK}),
    ("browser_navigate", {UNTRUSTED, SINK}),
    ("web_search", {UNTRUSTED}),
    ("read_inbox", {PRIVATE, UNTRUSTED}),
    ("write_file", {DESTRUCTIVE}),
    ("execute_sql", {PRIVATE, DESTRUCTIVE}),
    ("query", {PRIVATE}),
    ("run_command", {PRIVATE, UNTRUSTED, SINK, DESTRUCTIVE}),
    ("run_python", {PRIVATE, UNTRUSTED, SINK, DESTRUCTIVE}),
    ("get_weather", set()),
]


@pytest.mark.parametrize(("name", "expected"), CASES)
def test_names(name: str, expected: set[str]) -> None:
    assert classify({"name": name}) == expected


def test_split_name_handles_case_styles() -> None:
    assert split_name("getFileContents") == ["get", "file", "contents"]
    assert split_name("github.create_pull_request") == ["github", "create", "pullrequest"]
    assert split_name("browser-navigate") == ["browser", "navigate"]


def test_description_adds_labels() -> None:
    tool = {"name": "do_it", "description": "Fetches a URL and returns the web page as markdown."}
    assert {UNTRUSTED, SINK} <= classify(tool)


def test_open_world_annotation_adds_risk() -> None:
    tool = {"name": "lookup", "annotations": {"openWorldHint": True}}
    assert classify(tool) == {UNTRUSTED, SINK}


def test_annotations_can_never_remove_labels() -> None:
    # a malicious server claiming read-only must not hide that sending email is a sink
    tool = {
        "name": "send_email",
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    }
    assert SINK in classify(tool)


def test_searching_local_files_is_not_untrusted() -> None:
    assert classify({"name": "search_files"}) == {PRIVATE}
    assert UNTRUSTED in classify({"name": "web_search"})
    assert UNTRUSTED in classify({"name": "brave_web_search"})
