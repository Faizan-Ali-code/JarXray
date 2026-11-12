"""Credentials from the environment, and the SYSTEM-task folder permission check."""
from pathlib import Path

from jarxray import scheduler
from jarxray.config import load_config, resolve_secrets


def test_env_reference_and_empty_value_read_the_environment():
    config = {"NVD_API_KEY": "${MY_NVD}", "OPENAI_API_KEY": "", "SMTP_PASSWORD": "plain-text"}
    plain = resolve_secrets(config, {"MY_NVD": "nvd-from-env", "OPENAI_API_KEY": "sk-env"})
    assert config["NVD_API_KEY"] == "nvd-from-env" and config["OPENAI_API_KEY"] == "sk-env"
    assert plain == ["SMTP_PASSWORD"]


def test_placeholder_is_not_reported_as_a_plain_secret():
    config = {"NVD_API_KEY": "PUT-YOUR-NVD-API-KEY-HERE"}
    assert resolve_secrets(config, {}) == []


def test_config_file_with_env_reference(tmp_path, monkeypatch):
    path = tmp_path / "config.txt"
    path.write_text("DEPCHECK_BIN_FOLDER=tools\nDEPCHECK_BAT_NAME=dc.bat\nNVD_API_KEY=${NVD_API_KEY}\n"
                    "OUTPUT_FORMAT=HTML\n", encoding="utf-8")
    monkeypatch.setenv("NVD_API_KEY", "abc123")
    assert load_config(path)["NVD_API_KEY"] == "abc123"


def test_config_file_missing_secret_exits(tmp_path, monkeypatch, capsys):
    import pytest
    path = tmp_path / "config.txt"
    path.write_text("DEPCHECK_BIN_FOLDER=t\nDEPCHECK_BAT_NAME=d.bat\nNVD_API_KEY=${NVD_API_KEY}\nOUTPUT_FORMAT=HTML\n",
                    encoding="utf-8")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        load_config(path)
    assert "setx NVD_API_KEY" in capsys.readouterr().out


SAFE = r"""C:\Program Files\JarXray NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                         BUILTIN\Administrators:(I)(OI)(CI)(F)
                         BUILTIN\Users:(I)(OI)(CI)(RX)
                         CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files"""

UNSAFE = r"""C:\Tools\JarXray NT AUTHORITY\Authenticated Users:(I)(M)
                 NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)
                 NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                 BUILTIN\Administrators:(I)(OI)(CI)(F)
                 BUILTIN\Users:(I)(OI)(CI)(RX)
                 DESKTOP-1\alice:(OI)(CI)(WD,AD)

Successfully processed 1 files; Failed processing 0 files"""


def test_icacls_parsing():
    assert scheduler.writable_principals(SAFE, r"C:\Program Files\JarXray") == []
    assert scheduler.writable_principals(UNSAFE, r"C:\Tools\JarXray") == [
        "DESKTOP-1\\alice", "NT AUTHORITY\\Authenticated Users"]


def test_folders_checked_for_a_system_task(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyvenv.cfg").write_text(r"home = C:\Users\alice\AppData\Local\Programs\Python312" + "\n")
    seen = []

    def fake_icacls(folder):
        seen.append(folder)
        return UNSAFE.replace(r"C:\Tools\JarXray", str(folder)) if "alice" in str(folder) else None

    problems = scheduler.system_task_folders_problems(tmp_path, fake_icacls)
    assert seen == [tmp_path, Path(r"C:\Users\alice\AppData\Local\Programs\Python312")]
    assert problems == [(seen[1], ["DESKTOP-1\\alice", "NT AUTHORITY\\Authenticated Users"])]
