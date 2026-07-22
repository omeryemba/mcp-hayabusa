import asyncio

from mcp_hayabusa import hayabusa, server

EXPECTED_TOOL_NAMES = {
    "hayabusa_version",
    "hayabusa_list_profiles",
    "hayabusa_update_rules",
    "hayabusa_csv_timeline",
    "hayabusa_json_timeline",
    "hayabusa_eid_metrics",
    "hayabusa_logon_summary",
    "hayabusa_search",
}


def test_all_tools_registered():
    tools = asyncio.run(server.mcp.list_tools())
    assert {tool.name for tool in tools} == EXPECTED_TOOL_NAMES


def test_call_tool_version_routes_through(monkeypatch):
    monkeypatch.setattr(hayabusa, "version", lambda: "hayabusa v9.9.9")

    result = asyncio.run(server.mcp.call_tool("hayabusa_version", {}))

    assert "hayabusa v9.9.9" in str(result)


def test_call_tool_csv_timeline_passes_kwargs(monkeypatch):
    captured = {}

    def fake_csv_timeline(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa csv-timeline",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "rows": [],
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "csv_timeline", fake_csv_timeline)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_csv_timeline",
            {
                "target": "/some/path.evtx",
                "profile": "verbose",
                "min_level": "high",
                "rules_dir": "/rules",
                "max_rows": 50,
            },
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {
        "profile": "verbose",
        "min_level": "high",
        "rules_dir": "/rules",
        "max_rows": 50,
    }


def test_call_tool_eid_metrics_passes_kwargs(monkeypatch):
    captured = {}

    def fake_eid_metrics(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa eid-metrics",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "rows": [],
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "eid_metrics", fake_eid_metrics)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_eid_metrics",
            {"target": "/some/path.evtx", "max_rows": 50},
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {"max_rows": 50}


def test_call_tool_logon_summary_passes_kwargs(monkeypatch):
    captured = {}

    def fake_logon_summary(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        empty = {"total_rows": 0, "returned_rows": 0, "truncated": False, "rows": []}
        return {
            "command": "hayabusa logon-summary",
            "successful": empty,
            "failed": empty,
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "logon_summary", fake_logon_summary)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_logon_summary",
            {"target": "/some/path.evtx", "max_rows": 50},
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {"max_rows": 50}


def test_call_tool_search_passes_kwargs(monkeypatch):
    captured = {}

    def fake_search(target, keywords, **kwargs):
        captured["target"] = target
        captured["keywords"] = keywords
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa search",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "rows": [],
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "search", fake_search)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_search",
            {
                "target": "/some/path.evtx",
                "keywords": ["needle", "haystack"],
                "regex": True,
                "max_rows": 25,
            },
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["keywords"] == ["needle", "haystack"]
    assert captured["kwargs"] == {"regex": True, "max_rows": 25}
