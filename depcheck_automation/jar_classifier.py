"""
Internal jar separation: finds the organisation's own jars (the package /
groupId prefixes in INTERNAL_PACKAGES in config.txt) so that only
third-party jars are scanned.

A jar counts as internal when any ONE of three independent signals matches
a configured prefix. A single signal is not enough: a jar published under
Maven groupId com.example.pay.hub may have compiled classes that are NOT
under a com/example/ path.

  1. its file name (com.example-core.jar, example-core.jar, lib.example.jar)
  2. a compiled class under the prefix's path (com/example/...), also nested
     under BOOT-INF/classes or WEB-INF/classes
  3. a Maven groupId in its embedded pom.properties / pom.xml
"""
import os
import re
import shutil
import sys
import zipfile
import zlib
from collections import namedtuple
from datetime import datetime
from pathlib import Path

from .config import read_text_file
from .paths import ProjectPaths

# One resolved application to process: `name` is the display/identity name
# used for the Project Name default, report subfolder, and Application Code
# derivation; `path` is the actual folder on disk to read/scan. The name is
# the one written in front of the path (Name=path) when there is one, and
# otherwise the folder's own name - or, for a generic folder such as "lib",
# the name of the folder above it (see app_name_for).
AppFolder = namedtuple("AppFolder", ["name", "path"])

# Folder names that say nothing about which application they belong to: a
# configured D:\QA\OrderService\lib is named "OrderService", not "lib".
GENERIC_DIR_NAMES = {"lib", "libs", "jar", "jars", "web-inf", "boot-inf", "classes",
                     "dependency", "dependencies"}

# Never treated as an application folder. Most only matter for the pre-v2.3
# layout, where application folders sat next to the tool's own folders.
RESERVED_DIR_NAMES = {
    "apps", "config", "reports", "work", "tools", "dist", "docs", "tests", "scripts",
    "requirements", "depcheck_automation", "snapshots", "_dc_temp_output",
    "_live_lib_staging", "__pycache__", ".venv", "venv", "virtual",
}
INTERNAL_DIR_PREFIX = "internal_jars_"

GROUP_ID_XML_RE = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>", re.IGNORECASE)

# Everything zipfile can raise for a damaged or unusual archive/entry.
_ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, OSError, RuntimeError)


def internal_prefixes(config: dict) -> tuple:
    """INTERNAL_PACKAGES -> its package / groupId prefixes, e.g. ("com.example",).
    Empty means no jar is internal: every jar is scanned."""
    parts = re.split(r"[,;\s]+", config.get("INTERNAL_PACKAGES", "") or "")
    return tuple(p for p in (part.strip().strip(".") for part in parts) if p)


def filename_looks_internal(jar_path: Path, prefixes) -> bool:
    """com.example-core.jar, example-core.jar or lib.example.jar for prefix com.example."""
    name = jar_path.name.lower()
    for prefix in (p.lower() for p in prefixes):
        short = prefix.rsplit(".", 1)[-1]
        if name.startswith(prefix) or name.startswith(f"{short}-") or f".{short}." in name:
            return True
    return False


def group_id_is_internal(group_id: str, prefixes) -> bool:
    group_id = (group_id or "").lower()
    return any(group_id.startswith(prefix.lower()) for prefix in prefixes)


def _maven_metadata_is_internal(zf: zipfile.ZipFile, namelist: list, prefixes) -> bool:
    for name in namelist:
        if "META-INF/maven/" not in name or not name.endswith(("pom.properties", "pom.xml")):
            continue
        try:
            with zf.open(name) as f:
                content = f.read().decode("utf-8", errors="ignore")
        except _ZIP_ERRORS:
            continue  # one damaged entry must not hide the others
        if name.endswith("pom.properties"):
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("groupId=") and group_id_is_internal(line.split("=", 1)[1].strip(), prefixes):
                    return True
        elif any(group_id_is_internal(g, prefixes) for g in GROUP_ID_XML_RE.findall(content)):
            return True
    return False


def is_internal_jar(jar_path: Path, prefixes) -> bool:
    if not prefixes:
        return False

    # Signal 1: filename itself looks internal - cheap, check first
    if filename_looks_internal(jar_path, prefixes):
        return True

    # Path fragment (with slashes, as it appears inside a jar/zip) of an internal
    # class, whether it sits at the jar root or nested under something like
    # BOOT-INF/classes/ (Spring Boot fat jars) or WEB-INF/classes/.
    class_markers = tuple(prefix.replace(".", "/") + "/" for prefix in prefixes)
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            namelist = zf.namelist()

            # Signal 2: any compiled class living under an internal package path
            if any(name.endswith(".class") and any(m in name for m in class_markers) for name in namelist):
                return True

            # Signal 3: embedded Maven pom.properties/pom.xml groupId with an
            # internal prefix - catches jars whose Maven coordinates don't match
            # their actual Java package naming.
            return _maven_metadata_is_internal(zf, namelist, prefixes)
    except _ZIP_ERRORS:
        return False  # already checked filename above; nothing more we can inspect


# --------------------------------------------------------------------------- #
# Application folder discovery
# --------------------------------------------------------------------------- #
def has_jars(folder: Path) -> bool:
    """True if the folder holds a jar the scan would see: at any depth, the
    same rule dependency-check's recursive --scan follows (see _app_jars).
    A lib folder that keeps its jars in sub-folders, or an application root
    whose jars sit in WEB-INF\\lib, is an application folder too."""
    return any(True for _ in _iter_app_jars(folder))


def discover_app_folders(parent_dir: Path, nested: bool = True) -> list:
    """Every direct subfolder of parent_dir that contains .jar files (also in
    its own sub-folders, unless nested=False). Folders starting with '_' or
    '.' are skipped, so sample data can be parked (e.g. apps/_samples/)
    without being scanned on every run."""
    if not parent_dir.is_dir():
        return []
    app_folders = []
    for entry in sorted(parent_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name in RESERVED_DIR_NAMES or entry.name.startswith(("_", ".", INTERNAL_DIR_PREFIX)):
            continue
        if has_jars(entry) if nested else any(entry.glob("*.jar")):
            app_folders.append(entry)
    return app_folders


def app_name_for(path: Path) -> str:
    """The application a folder belongs to: its own name, unless that is a
    generic one like "lib" - then the first folder above it that is not."""
    for candidate in (path, *path.parents):
        if candidate.name and candidate.name.lower() not in GENERIC_DIR_NAMES:
            return candidate.name
    return path.name or "app"


def split_folder_entries(raw: str) -> list:
    """APP_FOLDERS -> its entries.

    Entries are separated by commas, semicolons or line breaks (config.txt
    may repeat APP_FOLDERS on several lines; see config.LIST_KEYS). Double
    quotes are optional around any entry, and needed only when a path itself
    contains a comma or semicolon. An unquoted # after a space starts a
    comment that runs to the end of that line.
    """
    entries, current, quoted, comment = [], [], False, False
    for ch in raw + "\n":
        if comment:
            if ch == "\n":
                comment = False
                entries.append("".join(current))
                current = []
            continue
        if ch == '"':
            quoted = not quoted
        elif quoted and ch != "\n":
            current.append(ch)
        elif ch in ",;\n":
            quoted = False
            entries.append("".join(current))
            current = []
        elif ch == "#" and (not current or current[-1].isspace()):
            comment = True
        else:
            current.append(ch)
    return [entry.strip() for entry in entries if entry.strip()]


def _split_name(entry: str) -> tuple:
    """'Name=path' -> (Name, path); a bare path -> (None, path). Whatever
    comes before the first '=' is a name unless it holds ':' or a backslash,
    which a path containing '=' always does and a name never needs."""
    name, sep, rest = entry.partition("=")
    if sep and not any(ch in name for ch in ":\\"):
        return name.strip(), rest.strip().strip('"').strip()
    return None, entry


def _as_paths(paths) -> ProjectPaths:
    return paths if isinstance(paths, ProjectPaths) else ProjectPaths(paths)


def _resolve_auto(paths: ProjectPaths) -> list:
    if paths.apps_dir.is_dir():
        return [AppFolder(p.name, p) for p in discover_app_folders(paths.apps_dir)]

    # Pre-v2.3 layout: application folders next to the tool's own folders.
    # Only folders that hold jars directly - anything deeper there is more
    # likely the tool's own clutter than an application.
    legacy = discover_app_folders(paths.root, nested=False)
    if legacy:
        print(f"NOTE: there is no apps\\ folder, so using the application folder(s) found next to the "
              f"tool (the pre-v2.3 layout): {', '.join(p.name for p in legacy)}")
        print(f"      Move them into {paths.apps_dir} when convenient.")
    return [AppFolder(p.name, p) for p in legacy]


def _app_folders_entries(config: dict) -> list:
    """[(source, name_or_None, raw_path), ...] from APP_FOLDERS."""
    return [("APP_FOLDERS", *_split_name(entry))
            for entry in split_folder_entries(config.get("APP_FOLDERS", ""))]


def _list_file_entries(paths: ProjectPaths, config: dict, required: bool) -> list:
    """[(source, name_or_None, raw_path), ...] from APP_LIST_FILE - one
    'AppName=path' (or just a path) per line, # comments and blank lines
    allowed. Without `required`, a missing list file simply means no entries."""
    list_file_raw = config.get("APP_LIST_FILE", "").strip()
    if not list_file_raw:
        if not required:
            return []
        print("ERROR: MODE=LIST_FILE in config.txt, but APP_LIST_FILE is empty.")
        print("Set APP_LIST_FILE to a text file listing 'AppName=path' entries, one per line.")
        sys.exit(1)

    list_file = paths.resolve_setting(list_file_raw)
    if not list_file.exists():
        if not required:
            return []
        print(f"ERROR: APP_LIST_FILE not found: {list_file}")
        sys.exit(1)

    entries = []
    for lineno, raw_line in enumerate(read_text_file(list_file, list_file.name).splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, raw_path = _split_name(line)
        source = f"{list_file.name} line {lineno}"
        if line.startswith("=") or name == "" or not raw_path:
            entries.append((source, line, None))  # reported as a problem below
            continue
        entries.append((source, name, raw_path))
    return entries


def _resolve_entries(paths: ProjectPaths, entries: list, problems) -> list:
    """Turns listed (source, name, raw_path) entries into AppFolders. Anything
    listed that cannot be scanned is printed and, when `problems` is a list,
    added to it as (name, reason) - a folder someone listed and that silently
    stopped being scanned (renamed by a redeploy, say) must fail the run."""
    resolved, names, folders = [], set(), set()

    def problem(source, name, reason):
        print(f"WARNING: {source} - {reason}")
        if problems is not None:
            problems.append((name, reason))

    for source, name, raw_path in entries:
        if raw_path is None:
            problem(source, name, f"expected 'AppName=Path' (or just a path), got: {name}")
            continue
        path = paths.resolve_app_folder(raw_path)
        label = name or app_name_for(path)
        if not path.is_dir():
            problem(source, label, f"folder not found: {path}")
            continue
        if not has_jars(path):
            problem(source, label, f"no .jar files in the folder or its sub-folders: {path}")
            continue

        folder_key = os.path.normcase(str(path.resolve()))
        if folder_key in folders:
            print(f"NOTE: {source} - {path} is already listed, scanning it once.")
            continue
        if name and name.lower() in names:
            problem(source, name, f"the name '{name}' is already used by another entry - give each one its own name")
            continue
        if not name:
            # Two lib folders of applications with the same folder name.
            name, attempt = label, 2
            while name.lower() in names:
                name, attempt = f"{label}_{attempt}", attempt + 1
        names.add(name.lower())
        folders.add(folder_key)
        resolved.append(AppFolder(name, path))
    return resolved


def resolve_app_folders(paths, config: dict, problems: list = None) -> list:
    """
    Returns a list of AppFolder(name, path). `paths` is a ProjectPaths (or the
    project root folder). Listed entries that cannot be scanned are printed
    and, if `problems` is a list, added to it as (name, reason).

    Application folders can be listed in APP_FOLDERS in config.txt (comma,
    semicolon or one line each) and/or in the APP_LIST_FILE text file, one
    'AppName=path' per line. Each path is a full path anywhere on disk (a
    deployed application's lib folder, typically) or a folder name inside
    apps/. MODE says which of these to use:

    AUTO (default): the folders listed in APP_FOLDERS and app_list.txt; when
    nothing is listed anywhere, every subfolder of apps/ that holds jars.
    LIST: only APP_FOLDERS.  LIST_FILE: only the APP_LIST_FILE file.
    """
    paths = _as_paths(paths)
    mode = config.get("MODE", "AUTO").strip().upper()

    if mode == "LIST_FILE":
        return _resolve_entries(paths, _list_file_entries(paths, config, required=True), problems)

    if mode == "LIST":
        entries = _app_folders_entries(config)
        if not entries:
            print("ERROR: MODE=LIST in config.txt, but APP_FOLDERS is empty.")
            print("Either list folders in APP_FOLDERS, or set MODE=AUTO.")
            sys.exit(1)
        return _resolve_entries(paths, entries, problems)

    entries = _app_folders_entries(config) + _list_file_entries(paths, config, required=False)
    if entries:
        print(f"Using the {len(entries)} application folder(s) listed in config "
              f"(APP_FOLDERS / APP_LIST_FILE); apps\\ is only scanned when nothing is listed.")
        return _resolve_entries(paths, entries, problems)
    return _resolve_auto(paths)


# --------------------------------------------------------------------------- #
# Which jars belong to an application folder
# --------------------------------------------------------------------------- #
def _iter_app_jars(app_dir: Path):
    return (
        jar for jar in app_dir.rglob("*.jar")
        if jar.is_file()
        and not any(part.startswith(INTERNAL_DIR_PREFIX) for part in jar.relative_to(app_dir).parts[:-1])
    )


def _app_jars(app_dir: Path) -> list:
    """Every jar under app_dir, at any depth, except inside internal_jars_* folders.

    Recursive on purpose: dependency-check's --scan of a directory is
    recursive, so a jar the classifier did not look at would still be scanned.
    """
    return sorted(_iter_app_jars(app_dir))


def is_inside(folder: Path, parent: Path) -> bool:
    try:
        Path(folder).resolve().relative_to(Path(parent).resolve())
        return True
    except ValueError:
        return False


def _unique_dir(parent: Path, stem: str) -> Path:
    # Second resolution only, so two runs starting within the same second (a
    # manual run racing the scheduled one) would otherwise share a folder.
    candidate, attempt = parent / stem, 2
    while candidate.exists():
        candidate = parent / f"{stem}_{attempt}"
        attempt += 1
    return candidate


# --------------------------------------------------------------------------- #
# Live-lib staging (SCAN_MODE=LIVE_LIB): copy, never touch, a real deployed
# application's lib folder
# --------------------------------------------------------------------------- #
def stage_copy_of_folder(source_dir: Path, staging_root: Path, name: str = None) -> Path:
    """
    Copies every .jar under source_dir (keeping sub-folders) into a freshly
    timestamped folder under staging_root, leaving source_dir completely
    untouched. Used when the configured app folder is a real, live/deployed
    application's lib directory rather than a staging folder this tool owns
    - separate_jars() below moves files, which would be unsafe to do
    directly inside a folder a running application still depends on.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    staging_dir = _unique_dir(staging_root, f"{name or source_dir.name}_{timestamp}")
    staging_dir.mkdir(parents=True)
    for jar in _app_jars(source_dir):
        target = staging_dir / jar.relative_to(source_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(jar), str(target))
    return staging_dir


# --------------------------------------------------------------------------- #
# Separation step (per application folder), with a verification safety net
# --------------------------------------------------------------------------- #
def _move(jar: Path, target: Path) -> bool:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(jar), str(target))
        return True
    except OSError as exc:
        # shutil.move falls back to copy + delete; a jar held open by another
        # process (antivirus, a running JVM) leaves the copy behind, which
        # would then exist twice. Undo the copy and report the jar instead.
        if jar.exists() and target.exists():
            try:
                target.unlink()
            except OSError:
                pass
        print(f"  WARNING: could not move {jar.name} ({exc}).")
        return False


def separate_jars(app_dir: Path, prefixes) -> tuple:
    """
    Moves internal jars (see is_internal_jar) out of app_dir into a freshly
    timestamped subfolder inside app_dir (keeping their sub-folder layout).
    Re-scans what's left as a safety net and retries anything that could not
    be moved.
    Returns (internal_dir_or_None, moved_count, remaining_count, leftover_internal_jars).
    """
    all_jars = _app_jars(app_dir)
    if not all_jars:
        return None, 0, 0, []

    internal_jars = [j for j in all_jars if is_internal_jar(j, prefixes)]

    internal_dir = None
    moved = 0
    if internal_jars:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        internal_dir = _unique_dir(app_dir, f"{INTERNAL_DIR_PREFIX}{timestamp}")
        internal_dir.mkdir(parents=True)
        for jar in internal_jars:
            moved += _move(jar, internal_dir / jar.relative_to(app_dir))

    # Safety net: re-scan whatever is left (excluding the internal folders) to
    # guarantee no internal jar remains, and retry once anything that is -
    # a lock held by another process is often only momentary.
    remaining_jars = _app_jars(app_dir)
    leftover_internal = [j for j in remaining_jars if is_internal_jar(j, prefixes)]
    if leftover_internal and internal_dir is not None:
        for jar in leftover_internal:
            moved += _move(jar, internal_dir / jar.relative_to(app_dir))
        remaining_jars = _app_jars(app_dir)
        leftover_internal = [j for j in remaining_jars if is_internal_jar(j, prefixes)]

    return internal_dir, moved, len(remaining_jars), leftover_internal
