"""Tests for the threat-intel correlation script (correlate_ti.py).

Same conventions as tests/test_ingest_ti.py: the script is loaded via
importlib since it lives outside src/mcp_hayabusa. Its
`analyze_coverage`/`suggest_rule` names are rebound into the loaded
module's own namespace by its `from mcp_hayabusa.knowledge import ...`
statement -- real, unmocked calls are made against a small real Sigma-rule
fixture directory built under tmp_path (same style as tests/test_knowledge.py's
`rules_dir` fixture), never mocked, since those functions are already
covered by their own tests in test_knowledge.py and this project's stated
convention is not to mock filesystem/parsing for these deterministic
scripts.
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
    / "correlate_ti.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("correlate_ti", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ct = _load_module()

COVERED_RULE = """\
title: Mimikatz Command Line
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects mimikatz usage via command line
tags:
    - attack.credential-access
    - attack.t1003.001
level: critical
"""


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "mimikatz.yml").write_text(COVERED_RULE, encoding="utf-8")
    return d


def _write_report(path, indicators, format_detected="native"):
    path.write_text(
        json.dumps({"file": str(path), "format_detected": format_detected, "indicators": indicators}),
        encoding="utf-8",
    )


# --- expand_ioc_paths ---


def test_expand_ioc_paths_file_passthrough(tmp_path):
    f = tmp_path / "norm.json"
    f.write_text("{}", encoding="utf-8")

    assert ct.expand_ioc_paths([str(f)]) == [f]


def test_expand_ioc_paths_directory_expands_to_json_glob(tmp_path):
    (tmp_path / "b.json").write_text("{}", encoding="utf-8")
    (tmp_path / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("x", encoding="utf-8")

    expanded = ct.expand_ioc_paths([str(tmp_path)])

    assert expanded == [tmp_path / "a.json", tmp_path / "b.json"]


# --- load_normalized_file ---


def test_load_normalized_file_valid(tmp_path):
    report = tmp_path / "norm.json"
    _write_report(report, [{"type": "ip", "value": "1.2.3.4"}])
    issues: list = []

    source_summary, indicators = ct.load_normalized_file(report, issues)

    assert issues == []
    assert source_summary == {"file": str(report), "format_detected": "native", "indicator_count": 1}
    assert indicators == [{"type": "ip", "value": "1.2.3.4"}]


def test_load_normalized_file_skips_malformed_entry(tmp_path):
    report = tmp_path / "norm.json"
    _write_report(report, [{"type": "ip"}, {"type": "ip", "value": "1.2.3.4"}])
    issues: list = []

    _source_summary, indicators = ct.load_normalized_file(report, issues)

    assert len(indicators) == 1
    assert any("skipped" in i for i in issues)


def test_load_normalized_file_missing_file_exits_2(tmp_path):
    with pytest.raises(SystemExit) as exc_info:
        ct.load_normalized_file(tmp_path / "nope.json", [])
    assert exc_info.value.code == 2


def test_load_normalized_file_wrong_shape_exits_2(tmp_path):
    report = tmp_path / "bad.json"
    report.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        ct.load_normalized_file(report, [])
    assert exc_info.value.code == 2


# --- merge_indicators ---


def test_merge_indicators_case_insensitive_dedup_and_confidence_max():
    indicators = [
        {"type": "ip", "value": "1.2.3.4", "confidence": 0.5, "source": "src-a",
         "first_seen": "2026-02-01"},
        {"type": "IP", "value": "1.2.3.4", "confidence": 0.9, "source": "src-b",
         "first_seen": "2026-01-01"},
    ]

    merged = ct.merge_indicators(indicators)

    assert len(merged) == 1
    entry = merged[0]
    assert entry["confidence"] == 0.9
    assert entry["source"] == ["src-a", "src-b"]
    assert entry["first_seen"] == "2026-01-01"
    assert entry["merged_from"] == 2


def test_merge_indicators_notes_joined_and_technique_carried():
    indicators = [
        {"type": "ip", "value": "1.2.3.4", "notes": "note-a", "attack_technique": "T1071.001"},
        {"type": "ip", "value": "1.2.3.4", "notes": "note-b", "attack_technique": None},
    ]

    merged = ct.merge_indicators(indicators)

    assert merged[0]["notes"] == "note-a; note-b"
    assert merged[0]["attack_technique"] == "T1071.001"


def test_merge_indicators_single_entry_passthrough():
    indicators = [{"type": "hash", "value": "abc123", "confidence": 0.5, "source": "src"}]

    merged = ct.merge_indicators(indicators)

    assert len(merged) == 1
    assert merged[0]["merged_from"] == 1
    assert merged[0]["source"] == ["src"]


# --- correlate_evidence ---


def test_correlate_evidence_match_found():
    merged = [{"value": "1.2.3.4"}]
    ct.correlate_evidence(merged, "log line mentions 1.2.3.4 twice, 1.2.3.4 again")

    assert merged[0]["observed_in_evidence"] is True
    assert merged[0]["evidence_match_count"] == 2


def test_correlate_evidence_no_match():
    merged = [{"value": "9.9.9.9"}]
    ct.correlate_evidence(merged, "nothing relevant here")

    assert merged[0]["observed_in_evidence"] is False
    assert merged[0]["evidence_match_count"] == 0


def test_correlate_evidence_no_evidence_text_given():
    merged = [{"value": "1.2.3.4"}]
    ct.correlate_evidence(merged, None)

    assert merged[0]["observed_in_evidence"] is False


def test_correlate_evidence_short_value_guard():
    merged = [{"value": "ab"}]
    ct.correlate_evidence(merged, "ab ab ab")

    assert merged[0]["observed_in_evidence"] is False
    assert merged[0]["evidence_match_count"] == 0


# --- build_technique_coverage ---


def test_build_technique_coverage_covered_and_uncovered(rules_dir):
    merged = [
        {"type": "hash", "value": "a", "attack_technique": "T1003.001", "notes": "mimikatz sample"},
        {"type": "ip", "value": "b", "attack_technique": "T1499", "notes": None},
    ]

    coverage = ct.build_technique_coverage(merged, str(rules_dir))
    by_id = {c["technique_id"]: c for c in coverage}

    assert by_id["T1003.001"]["covered"] is True
    assert by_id["T1003.001"]["rule_count"] == 1
    assert by_id["T1003.001"]["indicator_count"] == 1
    assert len(by_id["T1003.001"]["suggested_rules"]) >= 1

    assert by_id["T1499"]["covered"] is False
    assert by_id["T1499"]["rule_count"] == 0


def test_build_technique_coverage_ignores_null_technique(rules_dir):
    merged = [{"type": "ip", "value": "a", "attack_technique": None}]

    coverage = ct.build_technique_coverage(merged, str(rules_dir))

    assert coverage == []


# --- main() exit codes ---


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["correlate_ti.py", *argv])
    with pytest.raises(SystemExit) as exc_info:
        ct.main()
    return exc_info.value.code


def test_main_exits_0_clean_and_covered(tmp_path, monkeypatch, capsys, rules_dir):
    report = tmp_path / "norm.json"
    _write_report(report, [{"type": "hash", "value": "a", "attack_technique": "T1003.001"}])

    code = _run_main(monkeypatch, [str(report), "--rules-dir", str(rules_dir)])

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["techniques_uncovered"] == 0


def test_main_exits_1_when_technique_uncovered(tmp_path, monkeypatch, capsys, rules_dir):
    report = tmp_path / "norm.json"
    _write_report(report, [{"type": "ip", "value": "a", "attack_technique": "T1499"}])

    code = _run_main(monkeypatch, [str(report), "--rules-dir", str(rules_dir)])

    assert code == 1
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["techniques_uncovered"] == 1


def test_main_exits_1_when_indicator_skipped(tmp_path, monkeypatch, capsys, rules_dir):
    report = tmp_path / "norm.json"
    _write_report(report, [{"type": "ip"}])

    code = _run_main(monkeypatch, [str(report), "--rules-dir", str(rules_dir)])

    assert code == 1


def test_main_exits_2_on_missing_input_file(tmp_path, monkeypatch, capsys, rules_dir):
    code = _run_main(
        monkeypatch, [str(tmp_path / "nope.json"), "--rules-dir", str(rules_dir)]
    )

    assert code == 2


def test_main_exits_2_on_missing_hayabusa_result_path(tmp_path, monkeypatch, capsys, rules_dir):
    report = tmp_path / "norm.json"
    _write_report(report, [{"type": "ip", "value": "1.2.3.4"}])

    code = _run_main(
        monkeypatch,
        [str(report), "--rules-dir", str(rules_dir), "--hayabusa-result", str(tmp_path / "nope.json")],
    )

    assert code == 2


def test_main_evidence_correlation_end_to_end(tmp_path, monkeypatch, capsys, rules_dir):
    report = tmp_path / "norm.json"
    _write_report(report, [{"type": "ip", "value": "1.2.3.4", "attack_technique": "T1003.001"}])
    evidence = tmp_path / "scan.json"
    evidence.write_text(json.dumps({"records": ["seen 1.2.3.4 in the logs"]}), encoding="utf-8")

    code = _run_main(
        monkeypatch,
        [str(report), "--rules-dir", str(rules_dir), "--hayabusa-result", str(evidence)],
    )

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["observed_in_evidence"] == 1
    assert output["indicators"][0]["observed_in_evidence"] is True
