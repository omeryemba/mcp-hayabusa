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


def test_run_passes_stdin_devnull(monkeypatch):
    import subprocess

    captured = {}

    def fake_subprocess_run(command, **kwargs):
        captured["kwargs"] = kwargs

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    monkeypatch.setattr(hayabusa, "resolve_hayabusa_binary", lambda: "hayabusa")
    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)

    hayabusa._run(["help"])

    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL


def test_run_returns_partial_output_on_timeout(monkeypatch):
    import subprocess

    def fake_subprocess_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=command, timeout=kwargs["timeout"], output="partial out", stderr="partial err"
        )

    monkeypatch.setattr(hayabusa, "resolve_hayabusa_binary", lambda: "hayabusa")
    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)

    result = hayabusa._run(["config-critical-systems"], timeout_sec=5)

    assert result.returncode == hayabusa.TIMEOUT_RETURNCODE
    assert result.stdout == "partial out"
    assert result.stderr == "partial err"


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


def test_eid_metrics_parses_and_truncates(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["EventID", "Occurrences"])
            for i in range(5):
                writer.writerow([f"{4000 + i}", str(i)])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.eid_metrics(str(tmp_path), max_rows=2)

    assert result["total_rows"] == 5
    assert result["returned_rows"] == 2
    assert result["truncated"] is True
    assert result["rows"][0]["EventID"] == "4000"


def test_eid_metrics_missing_output_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, command=["hayabusa"])
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.eid_metrics(str(tmp_path))

    assert result["total_rows"] == 0
    assert result["rows"] == []
    assert result["truncated"] is False


def test_extract_base64_parses_and_truncates(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Decoded"])
            for i in range(5):
                writer.writerow([f"2024-01-01T00:00:0{i}Z", f"payload-{i}"])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.extract_base64(str(tmp_path), max_rows=2)

    assert result["total_rows"] == 5
    assert result["returned_rows"] == 2
    assert result["truncated"] is True
    assert result["rows"][0]["Decoded"] == "payload-0"


def test_extract_base64_missing_output_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, command=["hayabusa"])
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.extract_base64(str(tmp_path))

    assert result["total_rows"] == 0
    assert result["rows"] == []
    assert result["truncated"] is False


def test_log_metrics_parses_and_truncates(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Filename", "Total"])
            for i in range(5):
                writer.writerow([f"file{i}.evtx", str(i)])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.log_metrics(str(tmp_path), max_rows=2)

    assert result["total_rows"] == 5
    assert result["returned_rows"] == 2
    assert result["truncated"] is True
    assert result["rows"][0]["Filename"] == "file0.evtx"


def test_log_metrics_missing_output_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, command=["hayabusa"])
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.log_metrics(str(tmp_path))

    assert result["total_rows"] == 0
    assert result["rows"] == []
    assert result["truncated"] is False


def test_computer_metrics_parses_and_truncates(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        output_path = Path(args[args.index("-o") + 1])
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Computer", "Events"])
            for i in range(5):
                writer.writerow([f"HOST-{i}", str(i)])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.computer_metrics(str(tmp_path), max_rows=2)

    assert result["total_rows"] == 5
    assert result["returned_rows"] == 2
    assert result["truncated"] is True
    assert result["rows"][0]["Computer"] == "HOST-0"


def test_computer_metrics_missing_output_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, command=["hayabusa"])
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.computer_metrics(str(tmp_path))

    assert result["total_rows"] == 0
    assert result["rows"] == []
    assert result["truncated"] is False


def test_logon_summary_parses_both_files(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        prefix = Path(args[args.index("-o") + 1])
        with prefix.with_name(prefix.name + "-successful.csv").open(
            "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow(["Target Account", "Source Computer"])
            writer.writerow(["alice", "HOST-A"])
            writer.writerow(["bob", "HOST-B"])
        with prefix.with_name(prefix.name + "-failed.csv").open(
            "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow(["Target Account", "Source Computer"])
            writer.writerow(["mallory", "HOST-C"])
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.logon_summary(str(tmp_path), max_rows=1)

    assert result["successful"]["total_rows"] == 2
    assert result["successful"]["returned_rows"] == 1
    assert result["successful"]["truncated"] is True
    assert result["successful"]["rows"][0]["Target Account"] == "alice"
    assert result["failed"]["total_rows"] == 1
    assert result["failed"]["returned_rows"] == 1
    assert result["failed"]["truncated"] is False
    assert result["failed"]["rows"][0]["Target Account"] == "mallory"


def test_logon_summary_missing_files_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, command=["hayabusa"])
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.logon_summary(str(tmp_path))

    assert result["successful"] == {
        "total_rows": 0,
        "returned_rows": 0,
        "truncated": False,
        "rows": [],
    }
    assert result["failed"] == {
        "total_rows": 0,
        "returned_rows": 0,
        "truncated": False,
        "rows": [],
    }


def test_pivot_keywords_list_parses_and_truncates(tmp_path, monkeypatch):
    def fake_run(args, timeout_sec=600):
        prefix = Path(args[args.index("-o") + 1])
        prefix.with_name(prefix.name + "-Users.txt").write_text(
            "alice\nbob\ncarol\nmallory\n", encoding="utf-8"
        )
        prefix.with_name(prefix.name + "-IP Addresses.txt").write_text(
            "10.0.0.1\n10.0.0.2\n", encoding="utf-8"
        )
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.pivot_keywords_list(str(tmp_path), max_keywords=2)

    assert result["categories"]["Users"]["total_keywords"] == 4
    assert result["categories"]["Users"]["returned_keywords"] == 2
    assert result["categories"]["Users"]["truncated"] is True
    assert result["categories"]["Users"]["keywords"] == ["alice", "bob"]
    assert result["categories"]["IP Addresses"]["total_keywords"] == 2
    assert result["categories"]["IP Addresses"]["truncated"] is False


def test_pivot_keywords_list_min_level_flag_passed(tmp_path, monkeypatch):
    captured = {}

    def fake_run(args, timeout_sec=600):
        captured["args"] = args
        return FakeResult(returncode=0, command=["hayabusa", *args])

    monkeypatch.setattr(hayabusa, "_run", fake_run)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    hayabusa.pivot_keywords_list(str(tmp_path), min_level="high")

    args = captured["args"]
    assert args[args.index("-m") + 1] == "high"


def test_pivot_keywords_list_no_files_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, command=["hayabusa"])
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.pivot_keywords_list(str(tmp_path))

    assert result["categories"] == {}


def test_config_critical_systems_parses_none_found(tmp_path, monkeypatch):
    output = (
        "Some explanation text.\n\n"
        "Start time: 2026/01/01 00:00\n"
        "Total event log files: 1\n\n"
        "No DomainController found.\n\n"
        "No FileServer found.\n"
    )

    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, stdout=output)
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.config_critical_systems(str(tmp_path))

    assert result["prompt_interrupted"] is False
    assert result["categories"]["Domain Controllers"]["total_hosts"] == 0
    assert result["categories"]["Domain Controllers"]["hosts"] == []
    assert result["categories"]["File Servers"]["total_hosts"] == 0


def test_config_critical_systems_parses_found_and_truncates(tmp_path, monkeypatch):
    output = (
        "Some explanation text.\n\n"
        "Start time: 2026/01/01 00:00\n\n"
        "Domain Controllers found (2):\n"
        "DC1.contoso.local\n"
        "DC2.contoso.local\n\n"
        "No FileServer found.\n"
    )

    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, stdout=output)
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.config_critical_systems(str(tmp_path), max_hosts=1)

    assert result["prompt_interrupted"] is False
    dc = result["categories"]["Domain Controllers"]
    assert dc["total_hosts"] == 2
    assert dc["returned_hosts"] == 1
    assert dc["truncated"] is True
    assert dc["hosts"] == ["DC1.contoso.local"]
    assert result["categories"]["File Servers"]["total_hosts"] == 0


def test_config_critical_systems_timeout_returns_partial_results(tmp_path, monkeypatch):
    # Simulates hayabusa hanging on its interactive confirm prompt after
    # printing the Domain Controllers section but before reaching File
    # Servers -- _run surfaces this as TIMEOUT_RETURNCODE with partial stdout.
    output = (
        "Some explanation text.\n\n"
        "Domain Controllers found (1):\n"
        "DC1.contoso.local\n\n"
    )

    monkeypatch.setattr(
        hayabusa,
        "_run",
        lambda args, timeout_sec=600: FakeResult(
            returncode=hayabusa.TIMEOUT_RETURNCODE, stdout=output
        ),
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.config_critical_systems(str(tmp_path))

    assert result["prompt_interrupted"] is True
    assert result["categories"]["Domain Controllers"]["hosts"] == ["DC1.contoso.local"]
    assert "File Servers" not in result["categories"]


def test_config_critical_systems_strips_ansi_codes(tmp_path, monkeypatch):
    output = "\x1b[0mNo DomainController found.\n\n\x1b[0mNo FileServer found.\n"

    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=600: FakeResult(returncode=0, stdout=output)
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    result = hayabusa.config_critical_systems(str(tmp_path))

    assert result["categories"]["Domain Controllers"]["total_hosts"] == 0
    assert result["categories"]["File Servers"]["total_hosts"] == 0


def test_config_critical_systems_failure_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(
        hayabusa,
        "_run",
        lambda args, timeout_sec=600: FakeResult(returncode=2, stdout="", stderr="boom"),
    )
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)

    with pytest.raises(RuntimeError):
        hayabusa.config_critical_systems(str(tmp_path))


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


def _patch_scan_evtx_wrappers(monkeypatch, tmp_path, detection_rows=None):
    # scan_evtx must not shell out itself -- it should only call the
    # existing hayabusa.py wrapper functions. Monkeypatch those directly
    # (not _run) so a call to _run here would mean scan_evtx bypassed them.
    captured = {}
    if detection_rows is None:
        detection_rows = [{"RuleTitle": "Rule 0"}]

    def fake_log_metrics(target, **kwargs):
        captured["log_metrics"] = (target, kwargs)
        return {
            "command": "hayabusa log-metrics",
            "total_rows": 3,
            "returned_rows": 3,
            "truncated": False,
            "rows": [{"Filename": "a.evtx"}],
            "stderr_summary": "",
        }

    def fake_csv_timeline(target, **kwargs):
        captured["csv_timeline"] = (target, kwargs)
        return {
            "command": "hayabusa csv-timeline",
            "total_rows": 10,
            "returned_rows": len(detection_rows),
            "truncated": True,
            "rows": list(detection_rows),
            "stderr_summary": "",
        }

    def fake_eid_metrics(target, **kwargs):
        captured["eid_metrics"] = (target, kwargs)
        return {
            "command": "hayabusa eid-metrics",
            "total_rows": 7,
            "returned_rows": 7,
            "truncated": False,
            "rows": [{"EventID": "4624"}],
            "stderr_summary": "",
        }

    def fail_if_called(*args, **kwargs):
        raise AssertionError("_run must not be called directly by scan_evtx")

    monkeypatch.setattr(hayabusa, "log_metrics", fake_log_metrics)
    monkeypatch.setattr(hayabusa, "csv_timeline", fake_csv_timeline)
    monkeypatch.setattr(hayabusa, "eid_metrics", fake_eid_metrics)
    monkeypatch.setattr(hayabusa, "_run", fail_if_called)
    monkeypatch.setattr(hayabusa, "_require_existing_path", lambda p, label="target": tmp_path)
    return captured


def test_scan_evtx_full_composes_existing_wrappers(tmp_path, monkeypatch):
    captured = _patch_scan_evtx_wrappers(monkeypatch, tmp_path)

    result = hayabusa.scan_evtx(str(tmp_path), min_level="high", max_rows=50, output_format="full")

    assert result["target"] == str(tmp_path)
    assert result["min_level"] == "high"
    assert result["rule_filter"] is None
    assert result["output_format"] == "full"
    assert result["log_metrics"]["rows"] == [{"Filename": "a.evtx"}]
    assert result["detections"]["rows"] == [{"RuleTitle": "Rule 0"}]
    assert result["eid_metrics"]["rows"] == [{"EventID": "4624"}]
    assert result["summary"] == {
        "log_files_scanned": 3,
        "total_detections": 10,
        "matched_detections": 10,
        "detections_truncated": True,
        "distinct_event_ids": 7,
    }

    # min_level and max_rows must reach csv_timeline; the other two calls
    # only care about max_rows.
    assert captured["csv_timeline"][1]["min_level"] == "high"
    assert captured["csv_timeline"][1]["max_rows"] == 50
    assert captured["log_metrics"][1]["max_rows"] == 50
    assert captured["eid_metrics"][1]["max_rows"] == 50


def test_scan_evtx_default_output_format_is_summary(tmp_path, monkeypatch):
    _patch_scan_evtx_wrappers(monkeypatch, tmp_path)

    result = hayabusa.scan_evtx(str(tmp_path))

    assert result["output_format"] == "summary"
    assert "log_metrics" not in result
    assert "detections" not in result
    assert "eid_metrics" not in result
    assert result["summary"]["total_detections"] == 10
    assert result["top_findings"] == [{"RuleTitle": "Rule 0"}]


def test_scan_evtx_invalid_output_format_raises(tmp_path, monkeypatch):
    _patch_scan_evtx_wrappers(monkeypatch, tmp_path)

    with pytest.raises(ValueError):
        hayabusa.scan_evtx(str(tmp_path), output_format="verbose")


def test_scan_evtx_rule_filter_matches_case_insensitively(tmp_path, monkeypatch):
    rows = [
        {"RuleTitle": "Suspicious PowerShell Download"},
        {"RuleTitle": "Mimikatz Credential Dumping"},
        {"RuleTitle": "powershell Encoded Command"},
    ]
    _patch_scan_evtx_wrappers(monkeypatch, tmp_path, detection_rows=rows)

    result = hayabusa.scan_evtx(str(tmp_path), rule_filter="powershell", output_format="full")

    assert result["rule_filter"] == "powershell"
    assert result["detections"]["rows"] == [
        {"RuleTitle": "Suspicious PowerShell Download"},
        {"RuleTitle": "powershell Encoded Command"},
    ]
    assert result["detections"]["rule_filter_matches"] == 2
    assert result["summary"]["matched_detections"] == 2
    # total_detections stays the true hayabusa-reported total, unaffected
    # by rule_filter.
    assert result["summary"]["total_detections"] == 10


def test_scan_evtx_rule_filter_no_matches(tmp_path, monkeypatch):
    rows = [{"RuleTitle": "Suspicious PowerShell Download"}]
    _patch_scan_evtx_wrappers(monkeypatch, tmp_path, detection_rows=rows)

    result = hayabusa.scan_evtx(str(tmp_path), rule_filter="mimikatz")

    assert result["top_findings"] == []
    assert result["summary"]["matched_detections"] == 0


def test_scan_evtx_max_results_limits_findings(tmp_path, monkeypatch):
    rows = [{"RuleTitle": f"Rule {i}"} for i in range(5)]
    _patch_scan_evtx_wrappers(monkeypatch, tmp_path, detection_rows=rows)

    result = hayabusa.scan_evtx(str(tmp_path), max_results=2, output_format="full")

    assert result["detections"]["rows"] == [{"RuleTitle": "Rule 0"}, {"RuleTitle": "Rule 1"}]
    assert result["detections"]["returned_rows"] == 2
    # max_results only narrows detections/findings, not the true total.
    assert result["summary"]["total_detections"] == 10


def test_scan_evtx_max_results_default_preserves_prior_behavior(tmp_path, monkeypatch):
    rows = [{"RuleTitle": f"Rule {i}"} for i in range(5)]
    _patch_scan_evtx_wrappers(monkeypatch, tmp_path, detection_rows=rows)

    result = hayabusa.scan_evtx(str(tmp_path), output_format="full")

    # No max_results given -- all fetched rows pass through untouched, and
    # the detections dict is byte-identical to what csv_timeline returned.
    assert result["detections"]["rows"] == rows
    assert "rule_filter_matches" not in result["detections"]


def test_scan_evtx_target_must_exist(tmp_path):
    missing = tmp_path / "does-not-exist.evtx"
    with pytest.raises(FileNotFoundError):
        hayabusa.scan_evtx(str(missing))


def _write_rule(path, *, title, level="informational", status="stable", tags=None, description=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    tags_yaml = "\n".join(f"    - {t}" for t in (tags or []))
    path.write_text(
        f"""\
title: '{title}'
id: {path.stem}
level: {level}
status: {status}
description: '{description}'
tags:
{tags_yaml if tags_yaml else ""}
""",
        encoding="utf-8",
    )


def test_get_hayabusa_rules_lists_all_rules(tmp_path):
    _write_rule(tmp_path / "a.yml", title="Suspicious PowerShell Download")
    _write_rule(tmp_path / "sub" / "b.yml", title="Mimikatz Credential Dumping")

    result = hayabusa.get_hayabusa_rules(rules_dir=str(tmp_path))

    assert result["rules_dir"] == str(tmp_path)
    assert result["keyword"] is None
    assert result["rule_files_scanned"] == 2
    assert result["total_rules"] == 2
    assert result["returned_rules"] == 2
    assert result["truncated"] is False
    titles = {r["title"] for r in result["rules"]}
    assert titles == {"Suspicious PowerShell Download", "Mimikatz Credential Dumping"}


def test_get_hayabusa_rules_keyword_filters_case_insensitively(tmp_path):
    _write_rule(tmp_path / "a.yml", title="Suspicious PowerShell Download")
    _write_rule(tmp_path / "b.yml", title="Mimikatz Credential Dumping")
    _write_rule(
        tmp_path / "c.yml", title="Encoded Command", description="Detects powershell -enc usage"
    )

    result = hayabusa.get_hayabusa_rules(rules_dir=str(tmp_path), keyword="POWERSHELL")

    assert result["total_rules"] == 2
    titles = {r["title"] for r in result["rules"]}
    assert titles == {"Suspicious PowerShell Download", "Encoded Command"}


def test_get_hayabusa_rules_keyword_matches_tags(tmp_path):
    _write_rule(tmp_path / "a.yml", title="Rule A", tags=["attack.credential-access"])
    _write_rule(tmp_path / "b.yml", title="Rule B", tags=["attack.execution"])

    result = hayabusa.get_hayabusa_rules(rules_dir=str(tmp_path), keyword="credential-access")

    assert result["total_rules"] == 1
    assert result["rules"][0]["title"] == "Rule A"


def test_get_hayabusa_rules_no_matches(tmp_path):
    _write_rule(tmp_path / "a.yml", title="Rule A")

    result = hayabusa.get_hayabusa_rules(rules_dir=str(tmp_path), keyword="nonexistent")

    assert result["total_rules"] == 0
    assert result["rules"] == []
    assert result["truncated"] is False


def test_get_hayabusa_rules_truncates_with_max_rules(tmp_path):
    for i in range(5):
        _write_rule(tmp_path / f"rule{i}.yml", title=f"Rule {i}")

    result = hayabusa.get_hayabusa_rules(rules_dir=str(tmp_path), max_rules=2)

    assert result["total_rules"] == 5
    assert result["returned_rules"] == 2
    assert result["truncated"] is True
    assert len(result["rules"]) == 2


def test_get_hayabusa_rules_skips_unparseable_files(tmp_path):
    _write_rule(tmp_path / "good.yml", title="Good Rule")
    bad = tmp_path / "bad.yml"
    bad.write_text("title: [unterminated\n  - broken", encoding="utf-8")
    not_a_rule = tmp_path / "list.yml"
    not_a_rule.write_text("- just\n- a\n- list\n", encoding="utf-8")

    result = hayabusa.get_hayabusa_rules(rules_dir=str(tmp_path))

    assert result["rule_files_scanned"] == 3
    assert result["parse_errors"] == 2
    assert result["total_rules"] == 1
    assert result["rules"][0]["title"] == "Good Rule"


def test_get_hayabusa_rules_missing_rules_dir_raises(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(FileNotFoundError):
        hayabusa.get_hayabusa_rules(rules_dir=str(missing))


def test_get_hayabusa_rules_rules_dir_not_a_directory_raises(tmp_path):
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("hello", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        hayabusa.get_hayabusa_rules(rules_dir=str(not_a_dir))


def test_get_hayabusa_rules_default_rules_dir_next_to_binary(tmp_path, monkeypatch):
    fake_binary_dir = tmp_path / "hayabusa_install"
    rules_dir = fake_binary_dir / "rules"
    _write_rule(rules_dir / "a.yml", title="Rule A")

    fake_binary = fake_binary_dir / "hayabusa.exe"
    fake_binary_dir.mkdir(parents=True, exist_ok=True)
    fake_binary.write_text("", encoding="utf-8")

    monkeypatch.setattr(hayabusa, "resolve_hayabusa_binary", lambda: str(fake_binary))

    result = hayabusa.get_hayabusa_rules()

    assert result["rules_dir"] == str(rules_dir)
    assert result["total_rules"] == 1
