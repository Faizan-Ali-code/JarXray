"""
Installs OWASP dependency-check into tools/dependency-check - the folder the
settings template's DEPCHECK_BIN_FOLDER points at - so a fresh copy of the
tool (a git clone, say) needs no hand-made install. Run through
scripts\\setup_dependency_check.bat:

    (no option)       install, unless it is already there
    --reinstall       replace the install, keeping its NVD data
    --zip <file>      install from a release zip downloaded by hand (no internet)

The release is pinned: dc_json.py is verified against this version's JSON
report, and the zip must match the SHA-256 GitHub publishes for it, so a
changed or corrupted download is never installed.

dependency-check keeps its NVD database (~250 MB) in its own data folder. It
is built by the first scan and only topped up after that, so a reinstall
keeps it.
"""
import hashlib
import os
import shutil
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from .config import read_text_file
from .paths import ConfigLocationError, ProjectPaths

DC_VERSION = "12.2.2"
DOWNLOAD_URL = ("https://github.com/dependency-check/DependencyCheck/releases/download/"
                f"v{DC_VERSION}/dependency-check-{DC_VERSION}-release.zip")
DOWNLOAD_SHA256 = "bf07fefd81af3094c5f6850423b014df44db62ce2dbad0f79079a90df675e44a"
ZIP_TOP_FOLDER = "dependency-check"
DATA_FOLDER = "data"
BAT_NAME = "dependency-check.bat"
MAX_PATH = 260


class InstallError(Exception):
    """The install could not be done - the message says why."""


def installed_version(dc_dir: Path):
    """The version installed in dc_dir (read from its core jar's name), or None."""
    if not (dc_dir / "bin" / BAT_NAME).is_file():
        return None
    prefix = "dependency-check-core-"
    for jar in sorted((dc_dir / "lib").glob(prefix + "*.jar")):
        return jar.stem[len(prefix):]
    return "an unknown version"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, target: Path) -> None:
    """Saves url as target, via a .part file so an interrupted download never
    looks like a finished one."""
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    try:
        # The file is opened first, so a local problem (a path too long for
        # Windows, no write access) is reported as that, not as a network error.
        with open(partial, "wb") as out, urllib.request.urlopen(url, timeout=60) as response:
            total = int(response.headers.get("Content-Length") or 0)
            done, shown = 0, -1
            for block in iter(lambda: response.read(1 << 20), b""):
                out.write(block)
                done += len(block)
                if total and done * 10 // total != shown:
                    shown = done * 10 // total
                    print(f"    {done * 100 // total:3d}%  ({done / 1e6:.1f} of {total / 1e6:.1f} MB)", flush=True)
        partial.replace(target)
    finally:
        if partial.exists():
            partial.unlink()


def extract(zip_path: Path, dest: Path) -> Path:
    """Unpacks the release zip into dest and returns its dependency-check folder."""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():
                target = (dest / member).resolve()
                if target != root and root not in target.parents:
                    raise InstallError(f"the zip holds a path outside its own folder: {member}")
            zf.extractall(dest)
    except zipfile.BadZipFile as exc:
        raise InstallError(f"{zip_path} is not a readable zip ({exc})")
    unpacked = dest / ZIP_TOP_FOLDER
    if not (unpacked / "bin" / BAT_NAME).is_file():
        raise InstallError(f"the zip has no {ZIP_TOP_FOLDER}\\bin\\{BAT_NAME} - is it the dependency-check release?")
    return unpacked


def swap_in(unpacked: Path, dc_dir: Path) -> bool:
    """Puts the unpacked release at dc_dir. An existing install is replaced
    file by file, except its data folder (the NVD database), which is never
    moved or deleted - if a file is locked half-way, re-running finishes the
    job and the data is still there. Returns True when data was kept."""
    dc_dir.mkdir(parents=True, exist_ok=True)
    kept = (dc_dir / DATA_FOLDER).is_dir()
    for old in dc_dir.iterdir():
        if old.name == DATA_FOLDER:
            continue
        if old.is_dir():
            shutil.rmtree(old)
        else:
            old.unlink()
    for new in unpacked.iterdir():
        if new.name == DATA_FOLDER and kept:
            continue
        shutil.move(str(new), str(dc_dir / new.name))
    return kept


def _java_found() -> bool:
    # dependency-check.bat uses %JAVA_HOME%\bin\java.exe when JAVA_HOME is set,
    # otherwise java from PATH.
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        return (Path(java_home) / "bin" / "java.exe").is_file() or (Path(java_home) / "bin" / "java").is_file()
    return shutil.which("java") is not None


def _configured_bin_folder(paths: ProjectPaths):
    """DEPCHECK_BIN_FOLDER from config.txt as the tool resolves it, or None
    when there is no config.txt yet (the template already points here)."""
    try:
        config_file = paths.find_config_file()
    except ConfigLocationError:
        return None
    if not config_file.exists():
        return None
    value = None
    for line in read_text_file(config_file, "config.txt").splitlines():
        key, _, rest = line.strip().partition("=")
        if key.strip() == "DEPCHECK_BIN_FOLDER" and not line.strip().startswith("#"):
            value = rest.strip().strip("\"'")
    if not value:
        return None
    return paths.resolve_setting(value, config_file.parent)


def install(paths: ProjectPaths, zip_file: Path = None, reinstall: bool = False) -> int:
    dc_dir = paths.depcheck_dir
    current = installed_version(dc_dir)
    if current and not reinstall:
        print(f"dependency-check {current} is already installed in {dc_dir} - nothing to do.")
        print("(--reinstall replaces it with the pinned release, keeping its NVD data.)")
        return 0

    downloaded = zip_file is None
    if downloaded:
        zip_file = paths.download_dir / DOWNLOAD_URL.rsplit("/", 1)[1]
        if not (zip_file.is_file() and sha256_of(zip_file) == DOWNLOAD_SHA256):
            print(f"Downloading dependency-check {DC_VERSION} (about 29 MB):\n    {DOWNLOAD_URL}", flush=True)
            try:
                download(DOWNLOAD_URL, zip_file)
            except OSError as exc:
                # A local file (HTTPError carries the URL in .filename, so it is excluded)
                if exc.filename and not isinstance(exc, urllib.error.URLError):
                    print(f"\nERROR: could not write {exc.filename}: {exc.strerror}")
                    if len(str(exc.filename)) >= MAX_PATH - 10:
                        print(f"That path is {len(str(exc.filename))} characters long - Windows allows {MAX_PATH}. "
                              "Move the tool to a shorter folder,")
                        print("e.g. D:\\Tools\\dependency_check_automation, and run again.")
                    return 1
                print(f"\nERROR: the download failed: {exc}")
                print("If this machine reaches the internet through a proxy, set HTTPS_PROXY and run again.")
                print("Or download the zip above in a browser and run:")
                print('    scripts\\setup_dependency_check.bat --zip "<the downloaded zip>"')
                return 1
    elif not Path(zip_file).is_file():
        print(f"ERROR: {zip_file} not found.")
        return 1
    zip_file = Path(zip_file)

    actual = sha256_of(zip_file)
    if actual != DOWNLOAD_SHA256:
        print(f"\nERROR: {zip_file.name} is not the dependency-check {DC_VERSION} release - its SHA-256 differs.")
        print(f"    expected {DOWNLOAD_SHA256}\n    got      {actual}")
        if downloaded:
            zip_file.unlink()
            print("The download was deleted. Run again; if it keeps failing, something between this")
            print("machine and GitHub is changing the file.")
        else:
            print(f"Use dependency-check-{DC_VERSION}-release.zip from {DOWNLOAD_URL.rsplit('/', 1)[0]}/")
            print("(another version: install it yourself and point DEPCHECK_BIN_FOLDER at its bin folder).")
        return 1
    print("Checksum OK - the SHA-256 matches the one published for this release.")

    staging = paths.tools_dir / ".dependency-check.new"
    shutil.rmtree(staging, ignore_errors=True)
    try:
        kept = swap_in(extract(zip_file, staging), dc_dir)
    except InstallError as exc:
        print(f"\nERROR: {exc}")
        return 1
    except OSError as exc:
        print(f"\nERROR: could not replace {dc_dir}: {exc}")
        print("Is a scan running? Wait for it to finish (or close the window using that folder) and run")
        print("this again - the NVD data in its data folder is never touched.")
        return 1
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    if downloaded:
        zip_file.unlink()

    print(f"\nInstalled dependency-check {DC_VERSION} in:\n    {dc_dir}")
    if kept:
        print("Its NVD data (data folder) was kept, so the next scan only fetches what changed.")
    else:
        print("The first scan downloads the NVD vulnerability database into it (about 250 MB, using")
        print("NVD_API_KEY from config.txt), so it takes much longer than later scans, which only")
        print("fetch what changed. To skip that, copy the data folder of another install into it.")

    configured = _configured_bin_folder(paths)
    if configured is not None and Path(configured).resolve() != (dc_dir / "bin").resolve():
        print(f"\nNOTE: config.txt points DEPCHECK_BIN_FOLDER at {configured}.")
        print("To use this install, set:  DEPCHECK_BIN_FOLDER=tools\\dependency-check\\bin")
    if not _java_found():
        print("\nWARNING: Java was not found (neither JAVA_HOME nor java on PATH). dependency-check needs")
        print("Java 11 or newer to run - install it before the first scan.")
    return 0


def main(argv=None, paths: ProjectPaths = None) -> int:
    argv = list(argv or [])
    zip_file = None
    if "--zip" in argv:
        index = argv.index("--zip")
        if index + 1 >= len(argv):
            print('ERROR: --zip needs the path of the downloaded zip:  --zip "D:\\Downloads\\dependency-check.zip"')
            return 2
        zip_file = Path(argv[index + 1])
    return install(paths or ProjectPaths(), zip_file=zip_file, reinstall="--reinstall" in argv)
