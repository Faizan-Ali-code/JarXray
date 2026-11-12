"""
Internal jar separation: finds the organisation's own jars (the package /
groupId prefixes in INTERNAL_PACKAGES in config.txt) so that only
third-party code is scanned - without losing third-party code that is
packaged INSIDE an internal archive.

A jar counts as internal when its own content says so:
  1. a Maven groupId in its top-level META-INF/maven/<groupId>/... metadata
     starts with a configured prefix, or
  2. it has a compiled class directly under the prefix's package path
     (com/example/...), at the archive root or under BOOT-INF/classes or
     WEB-INF/classes.
The file name (com.example-core.jar, example-core.jar) is only used for a jar
that has neither classes nor Maven metadata, e.g. a resources-only jar: a
third-party jar that merely happens to be called example-something.jar is
not set aside.

Internal archives can carry third-party code, and setting them aside whole
would hide it from the scan:
  * fat jars / WARs / EARs bundle libraries (BOOT-INF/lib, WEB-INF/lib, lib/):
    those nested jars are extracted to a separate folder that is scanned too;
  * shaded jars contain third-party classes with that library's own Maven
    metadata: such an archive stays in the scan, and its internal coordinates
    are filtered out of the report instead (dc_json).
"""
import os
import re
import shutil
import sys
import zipfile
import zlib
from collections import namedtuple
from dataclasses import dataclass, field
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
    "requirements", "jarxray", "depcheck_automation", "snapshots", "_dc_temp_output",
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


def base_file_name(name: str) -> str:
    """The jar's own name from a dependency-check display name: "app.jar: lib.jar" (a file found inside
    another archive) -> "lib.jar"; "app.jar (shaded: g:a:v)" -> "app.jar"."""
    name = (name or "").split(" (shaded:", 1)[0]
    return name.rsplit(": ", 1)[-1].strip()


def filename_looks_internal(jar_path: Path, prefixes) -> bool:
    """com.example-core.jar, example-core.jar or lib.example.jar for prefix com.example."""
    name = base_file_name(Path(jar_path).name).lower()
    for prefix in (p.lower() for p in prefixes):
        short = prefix.rsplit(".", 1)[-1]
        if name.startswith(prefix) or name.startswith(f"{short}-") or f".{short}." in name:
            return True
    return False


def group_id_is_internal(group_id: str, prefixes) -> bool:
    """groupId equal to a prefix or below it: com.example, com.example.pay - but not com.examplecorp."""
    group_id = (group_id or "").lower()
    return any(group_id == p.lower() or group_id.startswith(p.lower() + ".") for p in prefixes)


# Where an archive keeps its own classes, and where it bundles other libraries.
CLASS_ROOTS = ("", "BOOT-INF/classes/", "WEB-INF/classes/")
NESTED_LIB_RE = re.compile(r"^(?:BOOT-INF/lib|WEB-INF/lib|APP-INF/lib|lib)/[^/]+\.jar$", re.IGNORECASE)
POM_PATH_RE = re.compile(r"^META-INF/maven/([^/]+)/[^/]+/pom\.(?:properties|xml)$")


@dataclass(frozen=True)
class JarInfo:
    """What a jar's content says about it."""
    internal: bool
    reason: str = ""                       # "maven groupId", "classes", "file name"
    nested_jars: tuple = ()                # bundled libraries: entry names inside the archive
    third_party_groups: tuple = ()         # non-internal groupIds in its own metadata = shaded code

    @property
    def shaded(self) -> bool:
        """An internal archive that also contains third-party classes (it must stay in the scan)."""
        return self.internal and bool(self.third_party_groups)


def _maven_group_ids(zf: zipfile.ZipFile, namelist: list) -> set:
    """groupIds of the archive's own top-level Maven metadata (path and pom.properties)."""
    groups = set()
    for name in namelist:
        match = POM_PATH_RE.match(name)
        if not match:
            continue
        groups.add(match.group(1))
        try:
            with zf.open(name) as f:
                content = f.read().decode("utf-8", errors="ignore")
        except _ZIP_ERRORS:
            continue  # one damaged entry must not hide the others
        if name.endswith("pom.properties"):
            groups.update(line.split("=", 1)[1].strip() for line in content.splitlines()
                          if line.strip().startswith("groupId="))
        else:
            groups.update(GROUP_ID_XML_RE.findall(content)[:1])  # the project's own groupId comes first
    return {g for g in groups if g}


def inspect_jar(jar_path: Path, prefixes) -> JarInfo:
    if not prefixes:
        return JarInfo(False)
    markers = tuple(root + prefix.replace(".", "/") + "/" for root in CLASS_ROOTS for prefix in prefixes)
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            namelist = zf.namelist()
            groups = _maven_group_ids(zf, namelist)
    except _ZIP_ERRORS:
        # Nothing inside can be read: the file name is the only evidence left.
        return JarInfo(True, "file name") if filename_looks_internal(jar_path, prefixes) else JarInfo(False)

    classes = [n for n in namelist if n.endswith(".class")]
    internal_groups = {g for g in groups if group_id_is_internal(g, prefixes)}
    if internal_groups:
        reason = "maven groupId"
    elif any(n.startswith(markers) for n in classes):
        reason = "classes"
    elif not classes and not groups and filename_looks_internal(jar_path, prefixes):
        reason = "file name"
    else:
        return JarInfo(False)
    nested = tuple(n for n in namelist if NESTED_LIB_RE.match(n))
    return JarInfo(True, reason, nested, tuple(sorted(groups - internal_groups)))


def is_internal_jar(jar_path: Path, prefixes) -> bool:
    return inspect_jar(jar_path, prefixes).internal


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


@dataclass
class Separation:
    """Outcome of separate_jars for one application folder."""
    internal_dir: Path = None          # where the internal jars were moved (None: none moved)
    moved: int = 0
    remaining: int = 0                 # jars left in the folder for the scan
    leftover_internal: list = field(default_factory=list)  # internal jars that could not be moved
    kept_shaded: list = field(default_factory=list)        # internal jars kept: they contain third-party code
    nested_extracted: list = field(default_factory=list)   # bundled third-party jars copied to nested_dir

    @property
    def to_scan(self) -> int:
        return self.remaining - len(self.leftover_internal) + len(self.nested_extracted)


def extract_nested_libraries(jar: Path, info: JarInfo, nested_dir: Path, prefixes) -> list:
    """Copies the libraries bundled in an internal archive (BOOT-INF/lib, WEB-INF/lib, lib/) into
    nested_dir/<archive>/ so they are scanned; bundled jars that are themselves internal are skipped."""
    extracted = []
    if not info.nested_jars:
        return extracted
    target_dir = _unique_dir(Path(nested_dir), jar.stem)
    target_dir.mkdir(parents=True)
    try:
        with zipfile.ZipFile(jar, "r") as zf:
            for entry in info.nested_jars:
                target = target_dir / Path(entry).name   # base name only: an entry can't write elsewhere
                with zf.open(entry) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                if is_internal_jar(target, prefixes):
                    target.unlink()
                else:
                    extracted.append(target)
    except _ZIP_ERRORS as exc:
        print(f"  WARNING: could not unpack the libraries bundled in {jar.name} ({exc}); they are not scanned.")
    return extracted


def separate_jars(app_dir: Path, prefixes, nested_dir: Path = None) -> Separation:
    """
    Moves internal jars out of app_dir into a freshly timestamped subfolder
    inside app_dir (keeping their sub-folder layout), so dependency-check
    scans only third-party code. Two exceptions keep third-party code in the
    scan:
      * an internal archive with shaded third-party classes stays where it is;
      * the libraries bundled in a moved archive are extracted into
        nested_dir (when given), which the caller scans as well.
    Re-scans what's left as a safety net and retries anything that could not
    be moved.
    """
    result = Separation()
    all_jars = _app_jars(app_dir)
    if not all_jars:
        return result

    infos = {jar: inspect_jar(jar, prefixes) for jar in all_jars}
    result.kept_shaded = [jar for jar, info in infos.items() if info.shaded]
    internal_jars = [jar for jar, info in infos.items() if info.internal and not info.shaded]

    if internal_jars:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        result.internal_dir = _unique_dir(app_dir, f"{INTERNAL_DIR_PREFIX}{timestamp}")
        result.internal_dir.mkdir(parents=True)
        for jar in internal_jars:
            if nested_dir is not None:
                result.nested_extracted += extract_nested_libraries(jar, infos[jar], nested_dir, prefixes)
            result.moved += _move(jar, result.internal_dir / jar.relative_to(app_dir))

    # Safety net: re-scan whatever is left (excluding the internal folders) to
    # guarantee no internal jar remains, and retry once anything that is -
    # a lock held by another process is often only momentary.
    def leftovers():
        return [j for j in _app_jars(app_dir) if j not in result.kept_shaded and is_internal_jar(j, prefixes)]

    result.leftover_internal = leftovers()
    if result.leftover_internal and result.internal_dir is not None:
        for jar in result.leftover_internal:
            result.moved += _move(jar, result.internal_dir / jar.relative_to(app_dir))
        result.leftover_internal = leftovers()
    result.remaining = len(_app_jars(app_dir))
    return result
