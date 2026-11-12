"""dependency-check is started without a shell, with every argument quoted, and unsafe values refused."""
from pathlib import Path

import pytest

from jarxray import scanner

CONFIG = {"OUTPUT_FORMAT": "HTML,CSV", "NVD_API_KEY": "secret-key-123", "EXTRA_ARGS": '--disableAssembly --x "a b"'}


def test_arguments_scan_every_folder_and_add_suppression():
    args = scanner.build_arguments({**CONFIG, "SUPPRESSION_FILE": r"D:\cfg\supp.xml"},
                                   [Path(r"D:\apps\A"), Path(r"D:\work\nested")], "A", Path(r"D:\out"), ["locked.jar"])
    assert args.count("--scan") == 2
    assert args[args.index("--suppression") + 1] == r"D:\cfg\supp.xml"
    assert {"HTML", "CSV", "JSON"} <= {args[i + 1] for i, a in enumerate(args) if a == "--format"}
    assert "**/locked.jar" in args and args[-2:] == ["--x", "a b"]


def test_command_line_quotes_everything():
    line = scanner.build_command_line(Path(r"C:\dc\bin\dependency-check.bat"), ["--scan", r"D:\R & D\lib (old)"])
    assert line == r'"C:\dc\bin\dependency-check.bat" "--scan" "D:\R & D\lib (old)"'


@pytest.mark.parametrize("value", [r"D:\100%DIR%\lib", 'D:\\a"b', "line\nbreak"])
def test_values_cmd_would_interpret_are_refused(value):
    with pytest.raises(scanner.UnsafeArgumentError):
        scanner.build_command_line(Path(r"C:\dc\dependency-check.bat"), ["--scan", value])


def test_refusal_message_does_not_leak_secrets():
    with pytest.raises(scanner.UnsafeArgumentError) as exc:
        scanner.build_command_line(Path("dc.bat"), ["--nvdApiKey", "key%1"])
    assert "key%1" not in str(exc.value)


def test_secrets_are_masked():
    assert scanner.mask_secrets(["--nvdApiKey", "abc", "--proxyPass=x", "--scan", "d"]) == \
        ["--nvdApiKey", "****", "--proxyPass=****", "--scan", "d"]


def test_split_extra_args():
    assert scanner.split_extra_args('--a "D:\\R & D\\s.xml" --b') == ["--a", "D:\\R & D\\s.xml", "--b"]


def test_run_starts_the_bat_without_a_shell(tmp_path, monkeypatch, capsys):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "dependency-check.bat").write_text("@echo off")
    calls = []

    class Done:
        returncode = 0

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Done()

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    config = {**CONFIG, "DEPCHECK_BIN_FOLDER": str(bin_dir), "DEPCHECK_BAT_NAME": "dependency-check.bat"}
    assert scanner.run_dependency_check(config, [tmp_path / "app"], "P", tmp_path / "out") == 0
    command, kwargs = calls[0]
    assert "shell" not in kwargs and kwargs["cwd"] == str(bin_dir)
    assert command.startswith(f'"{bin_dir / "dependency-check.bat"}" "--project" "P"')
    assert "secret-key-123" not in capsys.readouterr().out


def test_run_refuses_unsafe_folder(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "dependency-check.bat").write_text("")
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: pytest.fail("must not run"))
    config = {**CONFIG, "DEPCHECK_BIN_FOLDER": str(bin_dir), "DEPCHECK_BAT_NAME": "dependency-check.bat"}
    assert scanner.run_dependency_check(config, [tmp_path / "50%off"], "P", tmp_path / "out") == 1


def test_missing_bat(tmp_path):
    config = {**CONFIG, "DEPCHECK_BIN_FOLDER": str(tmp_path), "DEPCHECK_BAT_NAME": "dependency-check.bat"}
    assert scanner.run_dependency_check(config, [tmp_path], "P", tmp_path / "out") == 1
