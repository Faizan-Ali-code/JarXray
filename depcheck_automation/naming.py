"""Standard output filenames, shared by the raw HTML rename step and both generated reports."""
import re
from datetime import datetime

INVALID_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')

# Windows refuses these as file or folder names, with or without an extension.
_RESERVED_DEVICE_NAMES = {"CON", "PRN", "AUX", "NUL",
                          *(f"COM{i}" for i in range(1, 10)),
                          *(f"LPT{i}" for i in range(1, 10))}


def sanitize_for_filename(value: str) -> str:
    """Makes free text (e.g. an app name typed into app_list.txt) safe to use
    as ONE path component: no separators, no '.'/'..', no device names."""
    value = INVALID_FILENAME_CHARS.sub("_", value).strip().rstrip(" .")
    if not value:
        return "UNKNOWN"
    if value.split(".", 1)[0].strip().upper() in _RESERVED_DEVICE_NAMES:
        value = "_" + value
    return value


def build_report_filename(project_name: str, app_code: str, environment: str) -> str:
    return build_analysis_filename(project_name, app_code, environment, "dependency-check-report", "html")


def build_analysis_filename(project_name: str, app_code: str, environment: str, suffix: str, ext: str) -> str:
    date_str = datetime.now().strftime("%d-%m-%Y")
    project_name = sanitize_for_filename(project_name)
    app_code = sanitize_for_filename(app_code)
    environment = sanitize_for_filename(environment)
    return f"[{date_str}][{project_name}][{app_code}][{environment}][{suffix}].{ext}"
