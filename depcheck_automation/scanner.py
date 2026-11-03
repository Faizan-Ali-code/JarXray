"""Invokes dependency-check.bat against one application's remaining (third-party) jars."""
import re
import subprocess
from pathlib import Path

from .jar_classifier import INTERNAL_DIR_PREFIX

# dependency-check options whose value is a credential - never echoed to the
# console/log. By name rather than a fixed list: 12.2.2 alone has 19 of them
# (--nvdApiKey, --nexusPass, --kevBearerToken, --retireJsUrlPass, ...) and
# each release adds more.
_SECRET_FLAG_RE = re.compile(r"^--?\w*(pass|password|token|apikey|secret)$", re.IGNORECASE)


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


def _quote(arg: str) -> str:
    # Every argument, not just ones containing spaces: this command is handed
    # to cmd.exe as a single string (shell=True, see below), where an unquoted
    # &, (, ) or ^ in a real folder path would be taken as shell syntax.
    return f'"{arg}"'


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


def build_arguments(config: dict, scan_dir: Path, project_name: str, temp_out_dir: Path,
                    exclude_names=()) -> list:
    configured_formats = [f.strip().upper() for f in config["OUTPUT_FORMAT"].split(",") if f.strip()]
    for required_fmt in ("HTML", "JSON"):
        if required_fmt not in configured_formats:
            configured_formats.append(required_fmt)

    args = ["--project", project_name, "--scan", str(scan_dir)]

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

    args.extend(split_extra_args(config.get("EXTRA_ARGS", "")))
    return args


def run_dependency_check(config: dict, scan_dir: Path, project_name: str, temp_out_dir: Path,
                         exclude_names=()) -> int:
    bin_dir = Path(config["DEPCHECK_BIN_FOLDER"])
    if not bin_dir.is_absolute():
        # "cd /d <relative>" followed by "<relative>\dependency-check.bat" would
        # look for the .bat relative to the folder it just changed into.
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
    args = build_arguments(config, scan_dir, project_name, temp_out_dir, exclude_names)

    # Invoke via the batch file's full absolute path, not a bare/quoted name -
    # on at least one real machine, "cd /d ... && "dependency-check.bat" ..."
    # failed with "is not recognized as an internal or external command" even
    # though the file was confirmed present in that directory (the .bat had a
    # Windows "downloaded from the internet" mark-of-the-web flag, which seems
    # to be what broke bare-name resolution there). The full path works
    # regardless of cwd/PATH and sidesteps that entirely.
    full_command = f'cd /d "{bin_dir}" && "{bat_path}" ' + " ".join(_quote(a) for a in args)

    print(f"\n  Opening cmd at: {bin_dir}")
    print(f"  Running: {bat_path} " + " ".join(_quote(a) for a in mask_secrets(args)), flush=True)

    # Run as a single shell string (not ["cmd", "/c", full_command] as a list) -
    # passing it as a list element makes Python re-escape the quotes already
    # embedded in full_command, corrupting the cd /d "..." part.
    result = subprocess.run(full_command, shell=True)
    return result.returncode
