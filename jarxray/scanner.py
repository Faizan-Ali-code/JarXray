"""Invokes dependency-check.bat against one application's remaining (third-party) jars.

No shell is involved. The batch file is started directly (Windows runs a .bat
through cmd.exe itself), from its own folder, with every argument in double
quotes - so &, |, <, >, ^ and spaces in paths are taken literally. Two things
cmd.exe would still interpret inside quotes are refused instead of escaped:
a double quote (it would end the quoting) and % (it expands variables).
"""
import re
import subprocess
from pathlib import Path

from .jar_classifier import INTERNAL_DIR_PREFIX

# dependency-check options whose value is a credential - never echoed to the
# console/log. By name rather than a fixed list: 12.2.2 alone has 19 of them
# (--nvdApiKey, --nexusPass, --kevBearerToken, --retireJsUrlPass, ...) and
# each release adds more.
_SECRET_FLAG_RE = re.compile(r"^--?\w*(pass|password|token|apikey|secret)$", re.IGNORECASE)
_UNSAFE_FOR_CMD = re.compile(r'["%\r\n\x00]')


class UnsafeArgumentError(ValueError):
    """An argument cmd.exe would interpret even inside quotes."""


def _is_secret_flag(arg: str) -> bool:
    return bool(_SECRET_FLAG_RE.match(arg))


def split_extra_args(value: str) -> list:
    """EXTRA_ARGS -> arguments, the way a command prompt would split them:
    on spaces, except inside double quotes, which are then dropped. So
    --suppression "D:\\R & D\\supp.xml" stays one path."""
    args, current, quoted, started = [], [], False, False
    for ch in value:
        if ch == '"':
            quoted, started = not quoted, True
        elif ch.isspace() and not quoted:
            if started:
                args.append("".join(current))
            current, started = [], False
        else:
            current.append(ch)
            started = True
    if started:
        args.append("".join(current))
    return args


def mask_secrets(args: list) -> list:
    masked, hide_next = [], False
    for arg in args:
        if hide_next:
            masked.append("****")
            hide_next = False
            continue
        flag_part = arg.split("=", 1)[0]
        if "=" in arg and _is_secret_flag(flag_part):
            masked.append(flag_part + "=****")
            continue
        masked.append(arg)
        hide_next = _is_secret_flag(arg)
    return masked


def build_arguments(config: dict, scan_dirs, project_name: str, temp_out_dir: Path, exclude_names=()) -> list:
    """dependency-check arguments. scan_dirs: the application's folder, plus the folder of libraries
    extracted from internal archives (if any) - dependency-check accepts --scan more than once."""
    if isinstance(scan_dirs, (str, Path)):
        scan_dirs = [scan_dirs]
    configured_formats = [f.strip().upper() for f in config["OUTPUT_FORMAT"].split(",") if f.strip()]
    for required_fmt in ("HTML", "JSON"):
        if required_fmt not in configured_formats:
            configured_formats.append(required_fmt)

    args = ["--project", project_name]
    for scan_dir in scan_dirs:
        args.extend(["--scan", str(scan_dir)])

    # dependency-check scans a directory RECURSIVELY (it uses Ant's
    # DirectoryScanner), so without this the internal_jars_<timestamp> folder that
    # separate_jars() just created inside scan_dir - plus every previous run's
    # folder still sitting there - gets scanned right back in, defeating the
    # whole separation step and growing the scan a little more every day.
    args.extend(["--exclude", f"**/{INTERNAL_DIR_PREFIX}*/**"])
    # Internal jars that could not be moved aside (e.g. locked by another process).
    for name in exclude_names:
        args.extend(["--exclude", f"**/{name}"])

    for fmt in configured_formats:
        args.extend(["--format", fmt])
    args.extend(["--nvdApiKey", config["NVD_API_KEY"], "--out", str(temp_out_dir)])

    # Reviewed false positives: dependency-check's own suppression file format.
    suppression = (config.get("SUPPRESSION_FILE") or "").strip()
    if suppression:
        args.extend(["--suppression", suppression])

    args.extend(split_extra_args(config.get("EXTRA_ARGS", "")))
    return args


def build_command_line(bat_path: Path, args: list) -> str:
    """The command line handed to CreateProcess: program and arguments, each in double quotes."""
    everything = [str(bat_path), *args]
    shown_as = mask_secrets(everything)  # masked in context: a secret flag hides the value after it
    unsafe = [shown for value, shown in zip(everything, shown_as) if _UNSAFE_FOR_CMD.search(value)]
    if unsafe:
        shown = ", ".join(repr(a) for a in unsafe)
        raise UnsafeArgumentError(
            f"cannot pass {shown} to dependency-check.bat safely: cmd.exe treats \" and % specially even in "
            f"quotes. Rename the folder or change the setting so it contains neither character.")
    return " ".join(f'"{a}"' for a in [str(bat_path), *args])


def run_dependency_check(config: dict, scan_dirs, project_name: str, temp_out_dir: Path, exclude_names=()) -> int:
    bin_dir = Path(config["DEPCHECK_BIN_FOLDER"])
    if not bin_dir.is_absolute():
        bin_dir = bin_dir.resolve()
    bat_name = config["DEPCHECK_BAT_NAME"]
    bat_path = bin_dir / bat_name

    if not bat_path.exists():
        print(f"ERROR: {bat_name} not found in: {bin_dir}")
        print("Check DEPCHECK_BIN_FOLDER / DEPCHECK_BAT_NAME in config.txt, or install dependency-check")
        print("into tools\\dependency-check (where the template points) with:")
        print("    scripts\\setup_dependency_check.bat")
        return 1
    if "&" in str(bin_dir):
        # dependency-check.bat itself does an unquoted "set REPO=%BASEDIR%\lib",
        # which cmd cuts at the '&' - it then cannot find its own jar.
        print(f"  WARNING: the dependency-check folder contains '&', which dependency-check.bat itself "
              f"cannot handle - move it to a folder without '&': {bin_dir}")

    temp_out_dir.mkdir(parents=True, exist_ok=True)
    args = build_arguments(config, scan_dirs, project_name, temp_out_dir, exclude_names)
    try:
        command_line = build_command_line(bat_path, args)
    except UnsafeArgumentError as exc:
        print(f"  ERROR: {exc}")
        return 1

    print(f"\n  Running in {bin_dir}:")
    print(f"  {bat_path} " + " ".join(f'"{a}"' for a in mask_secrets(args)), flush=True)
    # The full path also sidesteps a bare-name lookup problem seen on one machine, where a .bat
    # downloaded from the internet (mark-of-the-web) was "not recognized" by name.
    result = subprocess.run(command_line, cwd=str(bin_dir))
    return result.returncode
