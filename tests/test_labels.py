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


CODEGRAPH = [
    "codegraph_search",
    "codegraph_explore",
    "codegraph_node",
    "codegraph_context",
    "codegraph_callers",
    "codegraph_callees",
    "codegraph_symbols",
    "codegraph_definition",
    "codegraph_references",
    "codegraph_impact",
]


def test_server_prefix_is_ignored_and_code_tools_are_private() -> None:
    unlabeled = [n for n in CODEGRAPH if not classify({"name": n}, server="codegraph")]
    assert unlabeled == []
    assert classify({"name": "codegraph_search"}, server="codegraph") == {PRIVATE}
    assert classify({"name": "codegraph_explore"}, server="code-graph") == {PRIVATE}


def test_prefix_stripping_keeps_meaningful_names() -> None:
    assert classify({"name": "slack_post_message"}, server="slack") == {SINK}
    assert SINK in classify({"name": "github_create_pull_request"}, server="github")
    assert classify({"name": "fetch"}, server="fetch") == {UNTRUSTED, SINK}  # never strips the whole name


def test_web_search_described_tools_stay_untrusted_after_prefix_strip() -> None:
    tool = {"name": "tavily_search", "description": "Search the web for real-time results."}
    assert UNTRUSTED in classify(tool, server="tavily")


def test_weather_is_still_unlabeled() -> None:
    assert classify({"name": "get_weather"}) == set()


def test_wikis_are_third_party_content() -> None:
    from kairoseki.labels import UNTRUSTED, classify

    assert UNTRUSTED in classify({"name": "read_wiki_contents"})  # e.g. DeepWiki's public repo wikis
