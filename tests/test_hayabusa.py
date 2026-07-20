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
    monkeypatch.setattr(
        hayabusa, "_run", lambda args, timeout_sec=30: FakeResult(stdout="hayabusa v3.0.0\n")
    )
    assert hayabusa.version() == "hayabusa v3.0.0"


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
