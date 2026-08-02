"""Tests for the threat-intel normalization script (ingest_ti.py).

The script under test lives outside src/mcp_hayabusa (.claude/skills/...),
so it isn't installed/importable as a normal module -- it's loaded directly
from its file path via importlib, the same way validate-rule-execution.py
is exercised in tests/test_validate_rule_execution.py.

No mocking of the parsing/normalization logic itself: every test writes a
real JSON file under tmp_path and asserts against the script's real output,
matching this project's convention (tests/test_knowledge.py) of never
mocking filesystem/parsing for these deterministic scripts.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / ".claude"
    / "skills"
    / "ingest-ti"
    / "scripts"
    / "ingest_ti.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("ingest_ti", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


it = _load_module()


# --- detect_format ---


def test_detect_format_misp_shape():
    data = {"Event": {"Attribute": [{"type": "ip-dst", "value": "1.2.3.4"}]}}
    assert it.detect_format(data) == "misp"


def test_detect_format_native_bare_list():
    assert it.detect_format([{"type": "ip", "value": "1.2.3.4"}]) == "native"


def test_detect_format_native_indicators_key():
    assert it.detect_format({"indicators": [{"type": "ip", "value": "1.2.3.4"}]}) == "native"


def test_detect_format_unrecognized_shape_returns_none():
    assert it.detect_format({"foo": "bar"}) is None
    assert it.detect_format("not a dict or list") is None


# --- normalize_native ---


def test_normalize_native_well_formed_entry_passthrough():
    data = [
        {
            "type": "ip",
            "value": "1.2.3.4",
            "confidence": 0.9,
            "source": "custom-source",
            "first_seen": "2026-01-01T00:00:00Z",
            "attack_technique": "T1071.001",
            "notes": "some note",
        }
    ]
    issues: list = []
    normalized, total = it.normalize_native(data, None, "stem", issues)

    assert total == 1
    assert issues == []
    assert normalized == [
        {
            "type": "ip",
            "value": "1.2.3.4",
            "confidence": 0.9,
            "source": "custom-source",
            "first_seen": "2026-01-01T00:00:00Z",
            "attack_technique": "T1071.001",
            "notes": "some note",
        }
    ]


def test_normalize_native_unsupported_type_coerced_to_other():
    data = [{"type": "weird-type", "value": "x"}]
    issues: list = []
    normalized, _total = it.normalize_native(data, None, "stem", issues)

    assert normalized[0]["type"] == "other"
    assert any("coerced to 'other'" in i for i in issues)


def test_normalize_native_missing_value_is_skipped():
    data = [{"type": "ip"}, {"type": "ip", "value": "1.2.3.4"}]
    issues: list = []
    normalized, total = it.normalize_native(data, None, "stem", issues)

    assert total == 2
    assert len(normalized) == 1
    assert any("skipped" in i for i in issues)


def test_normalize_native_defaults_confidence_and_source():
    data = [{"type": "ip", "value": "1.2.3.4"}]
    issues: list = []
    normalized, _total = it.normalize_native(data, None, "watchlist", issues)

    assert normalized[0]["confidence"] == it.DEFAULT_CONFIDENCE
    assert normalized[0]["source"] == "native:watchlist"


def test_normalize_native_source_label_overrides_default():
    data = [{"type": "ip", "value": "1.2.3.4"}]
    issues: list = []
    normalized, _total = it.normalize_native(data, "custom-label", "watchlist", issues)

    assert normalized[0]["source"] == "custom-label"


# --- normalize_misp ---


def _misp_event(attributes, info="Campaign X", event_date=None):
    event: dict = {"info": info, "Attribute": attributes}
    if event_date:
        event["date"] = event_date
    return {"Event": event}


def test_normalize_misp_type_mapping_table():
    data = _misp_event(
        [
            {"type": "ip-dst", "value": "1.2.3.4"},
            {"type": "sha256", "value": "a" * 64},
            {"type": "domain", "value": "example.com"},
            {"type": "url", "value": "http://example.com"},
            {"type": "unknown-type", "value": "x"},
        ]
    )
    issues: list = []
    normalized, total = it.normalize_misp(data, None, issues)

    assert total == 5
    types = [n["type"] for n in normalized]
    assert types == ["ip", "hash", "domain", "url", "other"]
    assert any("unmapped MISP type" in i for i in issues)


def test_normalize_misp_confidence_from_to_ids():
    data = _misp_event(
        [
            {"type": "ip-dst", "value": "1.2.3.4", "to_ids": True},
            {"type": "ip-dst", "value": "5.6.7.8", "to_ids": False},
        ]
    )
    issues: list = []
    normalized, _total = it.normalize_misp(data, None, issues)

    assert normalized[0]["confidence"] == it.MISP_TO_IDS_CONFIDENCE
    assert normalized[1]["confidence"] == it.DEFAULT_CONFIDENCE


def test_normalize_misp_epoch_timestamp_converted_to_iso():
    data = _misp_event([{"type": "ip-dst", "value": "1.2.3.4", "timestamp": "1785196800"}])
    issues: list = []
    normalized, _total = it.normalize_misp(data, None, issues)

    assert normalized[0]["first_seen"] == "2026-07-28T00:00:00+00:00"


def test_normalize_misp_falls_back_to_event_date():
    data = _misp_event([{"type": "ip-dst", "value": "1.2.3.4"}], event_date="2026-07-25")
    issues: list = []
    normalized, _total = it.normalize_misp(data, None, issues)

    assert normalized[0]["first_seen"] == "2026-07-25"


def test_normalize_misp_category_comment_joined_into_notes():
    data = _misp_event(
        [{"type": "ip-dst", "value": "1.2.3.4", "category": "Network activity", "comment": "C2 IP"}]
    )
    issues: list = []
    normalized, _total = it.normalize_misp(data, None, issues)

    assert normalized[0]["notes"] == "category=Network activity; comment=C2 IP"


def test_normalize_misp_attack_technique_always_null():
    data = _misp_event([{"type": "ip-dst", "value": "1.2.3.4"}])
    issues: list = []
    normalized, _total = it.normalize_misp(data, None, issues)

    assert normalized[0]["attack_technique"] is None


def test_normalize_misp_missing_value_is_skipped():
    data = _misp_event([{"type": "ip-dst"}])
    issues: list = []
    normalized, total = it.normalize_misp(data, None, issues)

    assert total == 1
    assert normalized == []
    assert any("skipped" in i for i in issues)


def test_normalize_misp_default_source_from_event_info():
    data = _misp_event([{"type": "ip-dst", "value": "1.2.3.4"}], info="Campaign X")
    issues: list = []
    normalized, _total = it.normalize_misp(data, None, issues)

    assert normalized[0]["source"] == "MISP:Campaign X"


# --- main() exit codes ---


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["ingest_ti.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        it.main()
    return exc_info.value.code


def test_main_exits_0_on_clean_native_file(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "iocs.json"
    input_path.write_text(
        json.dumps({"indicators": [{"type": "ip", "value": "1.2.3.4"}]}), encoding="utf-8"
    )

    code = _run_main(monkeypatch, [str(input_path)])

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is True
    assert output["format_detected"] == "native"
    assert len(output["indicators"]) == 1


def test_main_exits_1_when_an_indicator_is_skipped(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "iocs.json"
    input_path.write_text(
        json.dumps({"indicators": [{"type": "ip"}, {"type": "ip", "value": "1.2.3.4"}]}),
        encoding="utf-8",
    )

    code = _run_main(monkeypatch, [str(input_path)])

    assert code == 1
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is False
    assert output["checks"]["indicator_normalization"]["skipped"] == 1


def test_main_exits_2_on_missing_file(tmp_path, monkeypatch, capsys):
    code = _run_main(monkeypatch, [str(tmp_path / "nope.json")])

    assert code == 2
    output = json.loads(capsys.readouterr().out)
    assert output["valid"] is False


def test_main_exits_2_on_invalid_json(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "bad.json"
    input_path.write_text("{not valid json", encoding="utf-8")

    code = _run_main(monkeypatch, [str(input_path)])

    assert code == 2


def test_main_exits_2_on_unrecognized_shape(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "weird.json"
    input_path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")

    code = _run_main(monkeypatch, [str(input_path)])

    assert code == 2


def test_main_forced_format_mismatch_exits_2(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "native.json"
    input_path.write_text(json.dumps({"indicators": []}), encoding="utf-8")

    code = _run_main(monkeypatch, [str(input_path), "--format", "misp"])

    assert code == 2


def test_main_source_label_applied(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "iocs.json"
    input_path.write_text(
        json.dumps({"indicators": [{"type": "ip", "value": "1.2.3.4"}]}), encoding="utf-8"
    )

    code = _run_main(monkeypatch, [str(input_path), "--source-label", "custom-label"])

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["indicators"][0]["source"] == "custom-label"
