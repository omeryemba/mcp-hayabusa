import shutil

import pytest

from mcp_hayabusa import config


def test_hayabusa_bin_env_var_used_when_file_exists(tmp_path, monkeypatch):
    binary = tmp_path / "hayabusa"
    binary.write_text("")
    monkeypatch.setenv("HAYABUSA_BIN", str(binary))

    assert config.resolve_hayabusa_binary() == str(binary)


def test_hayabusa_bin_env_var_missing_file_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("HAYABUSA_BIN", str(tmp_path / "does-not-exist"))

    with pytest.raises(config.HayabusaNotFoundError):
        config.resolve_hayabusa_binary()


def test_falls_back_to_path_lookup_for_hayabusa(monkeypatch):
    monkeypatch.delenv("HAYABUSA_BIN", raising=False)
    monkeypatch.setattr(
        shutil, "which", lambda name: "/usr/bin/hayabusa" if name == "hayabusa" else None
    )

    assert config.resolve_hayabusa_binary() == "/usr/bin/hayabusa"


def test_falls_back_to_path_lookup_for_hayabusa_exe(monkeypatch):
    monkeypatch.delenv("HAYABUSA_BIN", raising=False)
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name: r"C:\tools\hayabusa.exe" if name == "hayabusa.exe" else None,
    )

    assert config.resolve_hayabusa_binary() == r"C:\tools\hayabusa.exe"


def test_raises_when_not_on_path(monkeypatch):
    monkeypatch.delenv("HAYABUSA_BIN", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    with pytest.raises(config.HayabusaNotFoundError):
        config.resolve_hayabusa_binary()
