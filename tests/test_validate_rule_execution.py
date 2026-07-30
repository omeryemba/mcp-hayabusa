"""Tests for the execution-based rule runner.

The script under test lives outside src/mcp_hayabusa (.claude/skills/...),
so it isn't installed/importable as a normal module -- it's loaded
directly from its file path via importlib, the same way any standalone
script would be exercised in tests. Its `csv_timeline`/`resolve_hayabusa_binary`
names are rebound into the loaded module's own namespace by its `from
mcp_hayabusa... import ...` statement, so tests monkeypatch those names on
the loaded module (not on mcp_hayabusa.hayabusa/.config directly) -- the
standard "patch where it's used" rule.

No real hayabusa binary or real .evtx fixture is ever needed here; every
test that would otherwise reach hayabusa monkeypatches `csv_timeline`.
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
    / "detection-engineering"
    / "scripts"
    / "validate-rule-execution.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_rule_execution", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vre = _load_module()


def _fake_csv_timeline(total_rows, hayabusa_errors=""):
    def fake(target, rules_dir):
        return {"total_rows": total_rows, "hayabusa_errors": hayabusa_errors}

    return fake


# --- iter_yaml_blocks ---


def test_iter_yaml_blocks_extracts_tagged_fences_only(tmp_path):
    content = """\
## Positive (must match)

Some rationale.

```yaml
fixture: foo.evtx
expect: fires
```

```
Channel: Security
EventID: 5140
```

## Negative (must not match)

```yaml
fixture: foo.evtx
expect: no_fire
```
"""
    testcases = tmp_path / "rule.testcases.md"
    testcases.write_text(content, encoding="utf-8")

    blocks = vre.iter_yaml_blocks(testcases)

    assert len(blocks) == 2
    assert blocks[0]["heading"] == "Positive (must match)"
    assert "fixture: foo.evtx" in blocks[0]["raw"]
    assert blocks[1]["heading"] == "Negative (must not match)"
    assert "expect: no_fire" in blocks[1]["raw"]


def test_iter_yaml_blocks_empty_file_returns_no_blocks(tmp_path):
    testcases = tmp_path / "rule.testcases.md"
    testcases.write_text("## Positive\n\nJust prose, no fences.\n", encoding="utf-8")

    assert vre.iter_yaml_blocks(testcases) == []


def test_iter_yaml_blocks_multiple_same_heading(tmp_path):
    content = """\
## Negative (must not match)

```yaml
fixture: a.evtx
expect: no_fire
```

```yaml
fixture: b.evtx
expect: no_fire
```
"""
    testcases = tmp_path / "rule.testcases.md"
    testcases.write_text(content, encoding="utf-8")

    blocks = vre.iter_yaml_blocks(testcases)
    assert len(blocks) == 2
    assert all(b["heading"] == "Negative (must not match)" for b in blocks)


# --- parse_case ---


def _block(raw, heading="Positive (must match)"):
    return {"heading": heading, "line": 1, "raw": raw}


def test_parse_case_valid_defaults_min_hits():
    result = vre.parse_case(_block("fixture: foo.evtx\nexpect: fires"))
    assert result["fixture"] == "foo.evtx"
    assert result["expect"] == "fires"
    assert result["min_hits"] == 1
    assert result["warning"] is None


def test_parse_case_valid_explicit_min_hits():
    result = vre.parse_case(_block("fixture: foo.evtx\nexpect: fires\nmin_hits: 3"))
    assert result["min_hits"] == 3


def test_parse_case_missing_fixture_is_parse_error():
    result = vre.parse_case(_block("expect: fires"))
    assert "parse_error" in result
    assert "fixture" in result["parse_error"]


def test_parse_case_invalid_expect_is_parse_error():
    result = vre.parse_case(_block("fixture: foo.evtx\nexpect: maybe"))
    assert "parse_error" in result


def test_parse_case_invalid_min_hits_is_parse_error():
    result = vre.parse_case(_block("fixture: foo.evtx\nexpect: fires\nmin_hits: 0"))
    assert "parse_error" in result


def test_parse_case_malformed_yaml_is_parse_error_not_silent_skip():
    result = vre.parse_case(_block("fixture: [unclosed"))
    assert "parse_error" in result
    assert "YAML syntax error" in result["parse_error"]


def test_parse_case_non_mapping_yaml_is_parse_error():
    result = vre.parse_case(_block("- just\n- a\n- list"))
    assert "parse_error" in result


def test_parse_case_heading_expect_mismatch_warns_not_fails():
    result = vre.parse_case(
        _block("fixture: foo.evtx\nexpect: fires", heading="Negative (must not match)")
    )
    assert "parse_error" not in result
    assert result["warning"] is not None
    assert "Negative" in result["warning"]


# --- resolve_fixture_dir ---


def test_resolve_fixture_dir_env_var_override(monkeypatch, tmp_path):
    monkeypatch.setenv("HAYABUSA_SAMPLE_EVTX_DIR", str(tmp_path))
    assert vre.resolve_fixture_dir() == tmp_path.resolve()


def test_resolve_fixture_dir_default_is_vendored_tests_fixtures(monkeypatch):
    monkeypatch.delenv("HAYABUSA_SAMPLE_EVTX_DIR", raising=False)
    result = vre.resolve_fixture_dir()
    assert result.parts[-2:] == ("fixtures", "evtx")


# --- run_case ---


def test_run_case_skips_when_hayabusa_unavailable(tmp_path):
    case = {"heading": "Positive", "fixture": "foo.evtx", "expect": "fires", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=False)
    assert result["outcome"] == "skipped"
    assert "hayabusa binary not found" in result["detail"]


def test_run_case_skips_when_fixture_missing(tmp_path):
    case = {"heading": "Positive", "fixture": "missing.evtx", "expect": "fires", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=True)
    assert result["outcome"] == "skipped"
    assert "fixture file not found" in result["detail"]


def test_run_case_fires_passes_when_hits_meet_threshold(tmp_path, monkeypatch):
    (tmp_path / "foo.evtx").write_bytes(b"fake")
    monkeypatch.setattr(vre, "csv_timeline", _fake_csv_timeline(total_rows=2))

    case = {"heading": "Positive", "fixture": "foo.evtx", "expect": "fires", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=True)

    assert result["outcome"] == "pass"
    assert result["hits"] == 2


def test_run_case_fires_fails_when_hits_below_threshold(tmp_path, monkeypatch):
    (tmp_path / "foo.evtx").write_bytes(b"fake")
    monkeypatch.setattr(vre, "csv_timeline", _fake_csv_timeline(total_rows=0))

    case = {"heading": "Positive", "fixture": "foo.evtx", "expect": "fires", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=True)

    assert result["outcome"] == "fail"


def test_run_case_no_fire_passes_on_zero_hits(tmp_path, monkeypatch):
    (tmp_path / "foo.evtx").write_bytes(b"fake")
    monkeypatch.setattr(vre, "csv_timeline", _fake_csv_timeline(total_rows=0))

    case = {"heading": "Negative", "fixture": "foo.evtx", "expect": "no_fire", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=True)

    assert result["outcome"] == "pass"


def test_run_case_no_fire_fails_on_any_hit(tmp_path, monkeypatch):
    (tmp_path / "foo.evtx").write_bytes(b"fake")
    monkeypatch.setattr(vre, "csv_timeline", _fake_csv_timeline(total_rows=1))

    case = {"heading": "Negative", "fixture": "foo.evtx", "expect": "no_fire", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=True)

    assert result["outcome"] == "fail"


def test_run_case_downgrades_to_error_on_hayabusa_errors_hint(tmp_path, monkeypatch):
    (tmp_path / "foo.evtx").write_bytes(b"fake")
    monkeypatch.setattr(
        vre, "csv_timeline", _fake_csv_timeline(total_rows=0, hayabusa_errors="Errors were generated...")
    )

    case = {"heading": "Negative", "fixture": "foo.evtx", "expect": "no_fire", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=True)

    assert result["outcome"] == "error"


def test_run_case_exception_from_csv_timeline_is_error(tmp_path, monkeypatch):
    (tmp_path / "foo.evtx").write_bytes(b"fake")

    def raise_runtime_error(target, rules_dir):
        raise RuntimeError("hayabusa exploded")

    monkeypatch.setattr(vre, "csv_timeline", raise_runtime_error)

    case = {"heading": "Positive", "fixture": "foo.evtx", "expect": "fires", "min_hits": 1}
    result = vre.run_case(case, Path("rule.yml"), tmp_path, hayabusa_available=True)

    assert result["outcome"] == "error"
    assert "hayabusa exploded" in result["detail"]


# --- run_rule / aggregation ---


def test_run_rule_errors_when_testcases_file_missing(tmp_path):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")

    result = vre.run_rule(rule_path, tmp_path, hayabusa_available=True)

    assert result["status"] == "error"
    assert "no non-empty sibling" in result["detail"]


def test_run_rule_errors_when_no_yaml_blocks(tmp_path):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text("## Positive\n\nprose only\n", encoding="utf-8")

    result = vre.run_rule(rule_path, tmp_path, hayabusa_available=True)

    assert result["status"] == "error"
    assert "no ```yaml execution-test blocks" in result["detail"]


def test_run_rule_all_skipped_when_hayabusa_unavailable(tmp_path):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text(
        "## Positive\n\n```yaml\nfixture: foo.evtx\nexpect: fires\n```\n", encoding="utf-8"
    )

    result = vre.run_rule(rule_path, tmp_path, hayabusa_available=False)

    assert result["status"] == "skipped"
    assert result["cases"][0]["outcome"] == "skipped"


def test_run_rule_pass_with_mixed_skipped_and_passed_cases(tmp_path, monkeypatch):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text(
        "## Positive\n\n```yaml\nfixture: present.evtx\nexpect: fires\n```\n\n"
        "## Negative\n\n```yaml\nfixture: missing.evtx\nexpect: no_fire\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "present.evtx").write_bytes(b"fake")
    monkeypatch.setattr(vre, "csv_timeline", _fake_csv_timeline(total_rows=1))

    result = vre.run_rule(rule_path, tmp_path, hayabusa_available=True)

    outcomes = {c["outcome"] for c in result["cases"]}
    assert outcomes == {"pass", "skipped"}
    assert result["status"] == "pass"


def test_run_rule_fail_beats_skipped(tmp_path, monkeypatch):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text(
        "## Positive\n\n```yaml\nfixture: present.evtx\nexpect: fires\n```\n\n"
        "## Negative\n\n```yaml\nfixture: missing.evtx\nexpect: no_fire\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "present.evtx").write_bytes(b"fake")
    monkeypatch.setattr(vre, "csv_timeline", _fake_csv_timeline(total_rows=0))

    result = vre.run_rule(rule_path, tmp_path, hayabusa_available=True)

    assert result["status"] == "fail"


def test_run_rule_error_beats_fail(tmp_path, monkeypatch):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text(
        "## Positive\n\n```yaml\nfixture: present.evtx\nexpect: fires\n```\n\n"
        "## Negative\n\n```yaml\nfixture: [unclosed\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "present.evtx").write_bytes(b"fake")
    monkeypatch.setattr(vre, "csv_timeline", _fake_csv_timeline(total_rows=0))

    result = vre.run_rule(rule_path, tmp_path, hayabusa_available=True)

    assert result["status"] == "error"


# --- expand_rule_paths ---


def test_expand_rule_paths_passes_through_files(tmp_path):
    f = tmp_path / "a.yml"
    f.write_text("title: a\n", encoding="utf-8")
    assert vre.expand_rule_paths([str(f)]) == [f]


def test_expand_rule_paths_expands_directory(tmp_path):
    (tmp_path / "b.yml").write_text("title: b\n", encoding="utf-8")
    (tmp_path / "a.yml").write_text("title: a\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("ignore me\n", encoding="utf-8")

    result = vre.expand_rule_paths([str(tmp_path)])

    assert [p.name for p in result] == ["a.yml", "b.yml"]


# --- main() exit codes ---


def _run_main(monkeypatch, argv, hayabusa_available=True, csv_timeline_fn=None):
    monkeypatch.setattr(sys, "argv", ["validate-rule-execution.py", *argv])
    if hayabusa_available:
        monkeypatch.setattr(vre, "resolve_hayabusa_binary", lambda: "/fake/hayabusa")
    else:

        def raise_not_found():
            raise vre.HayabusaNotFoundError("not found")

        monkeypatch.setattr(vre, "resolve_hayabusa_binary", raise_not_found)
    if csv_timeline_fn is not None:
        monkeypatch.setattr(vre, "csv_timeline", csv_timeline_fn)

    with pytest.raises(SystemExit) as exc_info:
        vre.main()
    return exc_info.value.code


def test_main_exits_0_when_all_cases_pass(tmp_path, monkeypatch, capsys):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text(
        "## Positive\n\n```yaml\nfixture: present.evtx\nexpect: fires\n```\n", encoding="utf-8"
    )
    (tmp_path / "present.evtx").write_bytes(b"fake")

    code = _run_main(
        monkeypatch,
        [str(rule_path), "--fixtures-dir", str(tmp_path)],
        csv_timeline_fn=_fake_csv_timeline(total_rows=1),
    )

    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["passed"] == 1


def test_main_exits_1_when_a_case_fails(tmp_path, monkeypatch, capsys):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text(
        "## Positive\n\n```yaml\nfixture: present.evtx\nexpect: fires\n```\n", encoding="utf-8"
    )
    (tmp_path / "present.evtx").write_bytes(b"fake")

    code = _run_main(
        monkeypatch,
        [str(rule_path), "--fixtures-dir", str(tmp_path)],
        csv_timeline_fn=_fake_csv_timeline(total_rows=0),
    )

    assert code == 1


def test_main_exits_2_when_testcases_file_missing(tmp_path, monkeypatch, capsys):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")

    code = _run_main(monkeypatch, [str(rule_path), "--fixtures-dir", str(tmp_path)])

    assert code == 2


def test_main_exits_3_when_hayabusa_unavailable(tmp_path, monkeypatch, capsys):
    rule_path = tmp_path / "myrule.yml"
    rule_path.write_text("title: test\n", encoding="utf-8")
    (tmp_path / "myrule.testcases.md").write_text(
        "## Positive\n\n```yaml\nfixture: present.evtx\nexpect: fires\n```\n", encoding="utf-8"
    )

    code = _run_main(
        monkeypatch, [str(rule_path), "--fixtures-dir", str(tmp_path)], hayabusa_available=False
    )

    assert code == 3
