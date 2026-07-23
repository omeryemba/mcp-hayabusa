import asyncio

from mcp_hayabusa import hayabusa, server

EXPECTED_TOOL_NAMES = {
    "hayabusa_version",
    "hayabusa_list_profiles",
    "hayabusa_update_rules",
    "hayabusa_csv_timeline",
    "hayabusa_json_timeline",
    "hayabusa_eid_metrics",
    "hayabusa_extract_base64",
    "hayabusa_log_metrics",
    "hayabusa_computer_metrics",
    "hayabusa_logon_summary",
    "hayabusa_pivot_keywords_list",
    "hayabusa_config_critical_systems",
    "hayabusa_search",
    "scan_evtx",
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


def test_call_tool_extract_base64_passes_kwargs(monkeypatch):
    captured = {}

    def fake_extract_base64(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa extract-base64",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "rows": [],
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "extract_base64", fake_extract_base64)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_extract_base64",
            {"target": "/some/path.evtx", "max_rows": 50},
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {"max_rows": 50}


def test_call_tool_log_metrics_passes_kwargs(monkeypatch):
    captured = {}

    def fake_log_metrics(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa log-metrics",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "rows": [],
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "log_metrics", fake_log_metrics)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_log_metrics",
            {"target": "/some/path.evtx", "max_rows": 50},
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {"max_rows": 50}


def test_call_tool_computer_metrics_passes_kwargs(monkeypatch):
    captured = {}

    def fake_computer_metrics(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa computer-metrics",
            "total_rows": 0,
            "returned_rows": 0,
            "truncated": False,
            "rows": [],
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "computer_metrics", fake_computer_metrics)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_computer_metrics",
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


def test_call_tool_pivot_keywords_list_passes_kwargs(monkeypatch):
    captured = {}

    def fake_pivot_keywords_list(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa pivot-keywords-list",
            "categories": {},
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "pivot_keywords_list", fake_pivot_keywords_list)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_pivot_keywords_list",
            {"target": "/some/path.evtx", "min_level": "high", "max_keywords": 50},
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {"min_level": "high", "max_keywords": 50}


def test_call_tool_config_critical_systems_passes_kwargs(monkeypatch):
    captured = {}

    def fake_config_critical_systems(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "command": "hayabusa config-critical-systems",
            "categories": {},
            "prompt_interrupted": False,
            "stderr_summary": "",
        }

    monkeypatch.setattr(hayabusa, "config_critical_systems", fake_config_critical_systems)

    asyncio.run(
        server.mcp.call_tool(
            "hayabusa_config_critical_systems",
            {"target": "/some/path.evtx", "max_hosts": 50},
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {"max_hosts": 50}


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


def test_call_tool_scan_evtx_passes_kwargs(monkeypatch):
    captured = {}

    def fake_scan_evtx(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "target": target,
            "min_level": kwargs.get("min_level"),
            "rule_filter": kwargs.get("rule_filter"),
            "output_format": kwargs.get("output_format", "summary"),
            "summary": {},
            "top_findings": [],
        }

    monkeypatch.setattr(hayabusa, "scan_evtx", fake_scan_evtx)

    asyncio.run(
        server.mcp.call_tool(
            "scan_evtx",
            {"target": "/some/path.evtx", "min_level": "high", "max_rows": 50},
        )
    )

    assert captured["target"] == "/some/path.evtx"
    assert captured["kwargs"] == {
        "min_level": "high",
        "rule_filter": None,
        "output_format": "summary",
        "max_results": None,
        "max_rows": 50,
    }


def test_call_tool_scan_evtx_passes_rule_filter_and_output_format(monkeypatch):
    captured = {}

    def fake_scan_evtx(target, **kwargs):
        captured["target"] = target
        captured["kwargs"] = kwargs
        return {
            "target": target,
            "min_level": None,
            "rule_filter": kwargs.get("rule_filter"),
            "output_format": kwargs.get("output_format"),
            "log_metrics": {},
            "detections": {},
            "eid_metrics": {},
            "summary": {},
        }

    monkeypatch.setattr(hayabusa, "scan_evtx", fake_scan_evtx)

    asyncio.run(
        server.mcp.call_tool(
            "scan_evtx",
            {
                "target": "/some/path.evtx",
                "rule_filter": "mimikatz",
                "output_format": "full",
                "max_results": 5,
            },
        )
    )

    assert captured["kwargs"] == {
        "min_level": None,
        "rule_filter": "mimikatz",
        "output_format": "full",
        "max_results": 5,
        "max_rows": 200,
    }
