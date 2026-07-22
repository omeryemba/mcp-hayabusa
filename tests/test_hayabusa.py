import csv
from pathlib import Path

import pytest

from mcp_hayabusa import hayabusa


class FakeResult:
    def __init__(self, returncode=0, stdout="", stderr="", command=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.command = command or []


def test_version(monkeypatch):
    help_output = (
        "Hayabusa v3.10.0 - Independence Day Release\n"
        "Yamato Security (https://github.com/Yamato-Security/hayabusa)\n"
        "\n"
        "Usage:\n"
        "  hayabusa.exe <COMMAND> [OPTIONS]\n"
    )
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=30: FakeResult(stdout=help_output)
    )
    assert hayabusa.version() == "v3.10.0 - Independence Day Release"


def test_version_calls_help_subcommand(monkeypatch):
    captured = {}

    def fake_run(args, timeout_sec=30):
        captured["args"] = args
        return FakeResult(stdout="Hayabusa v3.10.0 - Independence Day Release\n")

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    hayabusa.version()
    assert captured["args"] == ["help"]


def test_version_unparseable_output_raises(monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=30: FakeResult(stdout="unexpected output\n")
    )
    with pytest.raises(RuntimeError):
        hayabusa.version()


def test_csv_timeline_parses_and_truncates(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "RuleTitle", "Level"])
            for i in range(5):
                writer.writerow([f"2024-01-01T00:00:0{i}Z", f"Rule {i}", "high"])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.csv_timeline(str(tmp_path), max_rows=2)

    assert result["total_rows"] == 5
    assert result["returned_rows"] == 2
    assert result["truncated"] is True
    assert result["rows"][0]["RuleTitle"] == "Rule 0"


def test_csv_timeline_missing_output_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=1, stderr="boom")
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    with pytest.raises(RuntimeError):
        hayabusa.csv_timeline(str(tmp_path))


def test_search_requires_keywords(tmp_path, monkeypatch):
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)
    with pytest.raises(ValueError):
        hayabusa.search(str(tmp_path), [])


def test_target_must_exist(tmp_path):
    missing = tmp_path / "does-not-exist.evtx"
    with pytest.raises(FileNotFoundError):
        hayabusa._require_existing_path(str(missing))


def test_version_failure(monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=30: FakeResult(returncode=1)
    )
    with pytest.raises(RuntimeError):
        hayabusa.version()


def test_list_profiles_success(monkeypatch):
    monkeypatch.setattr(
        hayabusa,
        "_run",
        lambda args, timeout_sec=30: FakeResult(stdout="standard\nverbose\n"),
    )
    assert hayabusa.list_profiles() == "standard\nverbose"


def test_list_profiles_failure(monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=30: FakeResult(returncode=1, stderr="boom")
    )
    with pytest.raises(RuntimeError):
        hayabusa.list_profiles()


def test_update_rules_success(monkeypatch):
    monkeypatch.setattr(
        hayabusa,
        "_run",
        lambda args, timeout_sec=300: FakeResult(returncode=0, stdout="Rules updated.\n"),
    )
    assert hayabusa.update_rules() == "Rules updated."


def test_update_rules_already_up_to_date(monkeypatch):
    monkeypatch.setattr(
        hayabusa,
        "_run",
        lambda args, timeout_sec=300: FakeResult(returncode=1, stderr="already up to date"),
    )
    assert hayabusa.update_rules() == "already up to date"


def test_update_rules_failure(monkeypatch):
    monkeypatch.setattr(
        hayabusa,
        "_run",
        lambda args, timeout_sec=300: FakeResult(returncode=2, stderr="network error"),
    )
    with pytest.raises(RuntimeError):
        hayabusa.update_rules()


def test_json_timeline_parses_and_truncates(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", encoding="utf-8") as f:
            f.write("[\n")
            for i in range(5):
                f.write(f'{{"Timestamp": "2024-01-01T00:00:0{i}Z", "RuleTitle": "Rule {i}"}},\n')
            f.write("]\n")
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.json_timeline(str(tmp_path), max_rows=2)

    assert result["total_rows"] == 5
    assert result["returned_rows"] == 2
    assert result["truncated"] is True
    assert result["records"][0]["RuleTitle"] == "Rule 0"


def test_json_timeline_skips_invalid_json_line(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", encoding="utf-8") as f:
            f.write("[\n")
            f.write('{"Timestamp": "2024-01-01T00:00:00Z", "RuleTitle": "Rule 0"},\n')
            f.write("not valid json,\n")
            f.write("]\n")
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.json_timeline(str(tmp_path))

    assert result["total_rows"] == 2
    assert result["returned_rows"] == 1
    assert result["records"][0]["RuleTitle"] == "Rule 0"


def test_json_timeline_missing_output_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=1, stderr="boom")
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    with pytest.raises(RuntimeError):
        hayabusa.json_timeline(str(tmp_path))


def test_csv_timeline_optional_flags_passed(tmp_path, monkeypatch):
    captured = {}

    def fake_run(args, timeout_sec=600):
        captured["args"] = args
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp"])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    hayabusa.csv_timeline(
        str(tmp_path), profile="verbose", min_level="high", rules_dir="/rules"
    )

    args = captured["args"]
    assert args[args.index("-p") + 1] == "verbose"
    assert args[args.index("-m") + 1] == "high"
    assert args[args.index("-r") + 1] == "/rules"


def test_json_timeline_optional_flags_passed(tmp_path, monkeypatch):
    captured = {}

    def fake_run(args, timeout_sec=600):
        captured["args"] = args
        output_path = Path(args[args.index("-o") + 1])
        output_path.write_text("[\n]\n", encoding="utf-8")
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    hayabusa.json_timeline(
        str(tmp_path), profile="verbose", min_level="high", rules_dir="/rules"
    )

    args = captured["args"]
    assert args[args.index("-p") + 1] == "verbose"
    assert args[args.index("-m") + 1] == "high"
    assert args[args.index("-r") + 1] == "/rules"


def test_search_returns_results(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "RuleTitle"])
            writer.writerow(["2024-01-01T00:00:00Z", "match"])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.search(str(tmp_path), ["needle"])

    assert result["total_rows"] == 1
    assert result["returned_rows"] == 1
    assert result["truncated"] is False
    assert result["rows"][0]["RuleTitle"] == "match"


def test_search_uses_regex_flag(tmp_path, monkeypatch):
    captured = {}

    def fake_run(args, timeout_sec=600):
        captured["args"] = args
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["Timestamp"])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    hayabusa.search(str(tmp_path), ["a.*b"], regex=True)

    args = captured["args"]
    assert "-r" in args
    assert "-k" not in args
    assert args[args.index("-r") + 1] == "a.*b"


def test_search_missing_output_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=1, stderr="boom")
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.search(str(tmp_path), ["needle"])

    assert result["total_rows"] == 0
    assert result["returned_rows"] == 0
    assert result["rows"] == []
    assert result["truncated"] is False
