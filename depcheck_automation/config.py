"""config.txt loading/validation and the required-package startup check."""
import sys
from pathlib import Path

from .paths import ConfigLocationError, ProjectPaths

TRUTHY = ("yes", "y", "true", "1")

# Settings holding a file/folder path, with the default used when the key is
# absent. Relative values are resolved once, at load time (see ProjectPaths).
PATH_SETTINGS = {
    "DEPCHECK_BIN_FOLDER": None,
    "APP_LIST_FILE": None,
    "AI_PROMPT_FILE": "prompt_template.txt",
    "AI_CACHE_FILE": "ai_recommendation_cache.json",
    "SMTP_CA_BUNDLE": None,
}

VALID_MODES = ("AUTO", "LIST", "LIST_FILE")
VALID_SCAN_MODES = ("STAGING", "LIVE_LIB")

# Keys that may be written on several lines, one application per line; the
# lines add up. Any other key written twice: the last one wins, with a warning.
LIST_KEYS = ("APP_FOLDERS",)

# Values the shipped template carries until someone fills them in.
PLACEHOLDER_PREFIXES = ("PUT-YOUR-", "C:\\PATH\\TO\\")


def flag(config: dict, key: str, default: str = "no") -> bool:
    """A yes/no setting."""
    return str(config.get(key, default) or default).strip().lower() in TRUTHY


def read_text_file(path: Path, label: str) -> str:
    """Reads a user-edited text file whatever Notepad or PowerShell saved it as.

    PowerShell 5.1 and older Notepad add a UTF-8 BOM (which str.strip() does
    not remove, so it would end up inside the first key or app name), and
    PowerShell's '>' writes UTF-16. Anything else that is not UTF-8 gets a
    clear instruction instead of a traceback.
    """
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        print(f"ERROR: {label} ({path}) is not saved as UTF-8 (unreadable byte at position {exc.start}).")
        print("Open it in Notepad, choose File > Save As > Encoding: UTF-8, save, and run again.")
        sys.exit(1)


def _unquote(value: str) -> str:
    # Only a value that is ONE quoted string: "D:\a","D:\b" is two quoted
    # entries of a list, and stripping its outer quotes would glue them.
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'" and value[0] not in value[1:-1]:
        return value[1:-1].strip()
    return value


def check_required_packages(need_openai: bool) -> None:
    missing = []
    try:
        import odf  # noqa: F401
    except ImportError:
        missing.append("odfpy")

    openai_too_old = False
    if need_openai:
        try:
            import openai
            # The Responses API (client.responses) arrived in openai 1.66.0.
            openai_too_old = not hasattr(openai.OpenAI, "responses")
        except ImportError:
            missing.append("openai")

    if not missing and not openai_too_old:
        return

    if getattr(sys, "frozen", False):
        print("\nERROR: this .exe was built without: " + ", ".join(missing or ["openai>=1.66"]))
        print("Rebuild it with scripts\\build_release.bat from a checkout whose .venv was set up by")
        print("scripts\\setup_venv.bat.")
        sys.exit(1)

    if missing:
        print("\nERROR: missing required Python package(s): " + ", ".join(missing))
    if openai_too_old:
        print("\nERROR: the installed 'openai' package is too old (needs 1.66.0 or newer for the "
              "Responses API used when ENABLE_AI=yes).")
    print(f"Python interpreter currently running this tool:\n    {sys.executable}")
    print("\nFix - from the tool's folder, run once:")
    print("    scripts\\setup_venv.bat")
    print("(creates .venv and installs everything; run_dependency_check.bat then uses it automatically)")
    print("or install into the interpreter shown above yourself:")
    print(f'    "{sys.executable}" -m pip install -r requirements\\runtime.txt')
    sys.exit(1)


def load_config(config_path: Path) -> dict:
    config_path = Path(config_path)
    if not config_path.exists():
        print(f"ERROR: config.txt not found at {config_path}")
        sys.exit(1)

    config, first_seen = {}, {}
    for lineno, line in enumerate(read_text_file(config_path, "config.txt").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), _unquote(value.strip())
        if key in first_seen:
            if key in LIST_KEYS:
                config[key] = "\n".join(v for v in (config[key], value) if v)
                continue
            print(f"WARNING: {key} is set more than once in config.txt (lines {first_seen[key]} and "
                  f"{lineno}) - the value on line {lineno} is used.")
        first_seen.setdefault(key, lineno)
        config[key] = value

    required = ["DEPCHECK_BIN_FOLDER", "DEPCHECK_BAT_NAME", "NVD_API_KEY", "OUTPUT_FORMAT"]
    if flag(config, "ENABLE_AI"):
        required.append("OPENAI_API_KEY")
    if flag(config, "EMAIL_ENABLED"):
        required += ["SMTP_SERVER", "EMAIL_RECIPIENTS"]

    missing = [k for k in required if not config.get(k)]
    if missing:
        print(f"ERROR: config.txt is missing values for: {', '.join(missing)}")
        print(f"    ({config_path})")
        sys.exit(1)

    placeholders = [k for k in required if config[k].upper().startswith(PLACEHOLDER_PREFIXES)]
    if placeholders:
        print(f"ERROR: config.txt still has the template's placeholder value for: {', '.join(placeholders)}")
        print(f"Open {config_path} in Notepad and fill in your own values.")
        sys.exit(1)

    # A typo here must never fall back to the default: SCAN_MODE=STAGING moves
    # jars, which is exactly what LIVE_LIB exists to prevent in a live lib folder.
    for key, allowed, default in (("MODE", VALID_MODES, "AUTO"),
                                  ("SCAN_MODE", VALID_SCAN_MODES, "STAGING")):
        value = (config.get(key) or default).strip().upper()
        if value not in allowed:
            print(f"ERROR: {key}={config.get(key)!r} in config.txt is not one of: {', '.join(allowed)}")
            sys.exit(1)
        config[key] = value

    return config


def load_project_config(paths: ProjectPaths) -> tuple:
    """(config, config_file) for this install. Creates config/config.txt from
    the template on the very first run, and turns every path setting into an
    absolute path so nothing downstream depends on the current directory."""
    try:
        config_file = paths.find_config_file()
        if not config_file.exists():
            created = paths.create_config_from_template()
            print(f"\nFirst run: created your settings file from the template:\n    {created}")
            print("Open it in Notepad, fill in at least NVD_API_KEY (and DEPCHECK_BIN_FOLDER, unless")
            print("dependency-check is in tools\\dependency-check - see scripts\\setup_dependency_check.bat),")
            print("save, and run again.")
            sys.exit(1)
    except ConfigLocationError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    for created in paths.create_missing_starter_files():
        print(f"Created {created} from its template.")
    config = load_config(config_file)
    for key, default in PATH_SETTINGS.items():
        value = (config.get(key) or default or "").strip()
        if value:
            config[key] = str(paths.resolve_setting(value, config_file.parent))
    return config, config_file
