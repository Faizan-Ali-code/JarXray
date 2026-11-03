"""
Where everything lives. This is the only module that knows the folder layout,
so the scan, the scheduler, the frozen .exe and the tests all agree on it:

    <root>/
      run_dependency_check.bat    entry point (also next to the .exe in the portable release)
      config/                     config.txt, app_list.txt, prompt_template.txt, AI cache
      apps/<AppName>/*.jar        input when config.txt lists no lib folders - one per application
      reports/<AppName>/          output
      work/                       disposable scratch space (scan output, LIVE_LIB copies, downloads)
      tools/dependency-check/     OWASP dependency-check, put there by --install-dependency-check

Relative paths inside config.txt are looked up next to config.txt first and
then in <root>, so a settings file written for the older flat layout (where
everything sat next to the .bat) keeps working unchanged.
"""
import shutil
import sys
from pathlib import Path

CONFIG_FILE_NAME = "config.txt"
CONFIG_TEMPLATE_NAME = "config.template.txt"

# The other settings files, and the starting point each is created from. The
# packages ship only the starting points, so unpacking a new version over an
# install can't overwrite an install's application list or tuned AI prompt.
STARTER_FILES = {"app_list.txt": "app_list.template.txt",
                 "prompt_template.txt": "prompt_template.default.txt"}


class ConfigLocationError(Exception):
    """config.txt could not be settled on - the message says what to do."""


def project_root() -> Path:
    """The folder holding run_dependency_check.bat.

    Frozen by PyInstaller, sys.executable is the .exe itself and __file__
    points into a temporary unpack folder (_MEIxxxx), so the root must come
    from the executable. Otherwise it is the parent of this package.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


class ProjectPaths:
    def __init__(self, root: Path = None):
        self.root = Path(root) if root is not None else project_root()
        self.config_dir = self.root / "config"
        self.apps_dir = self.root / "apps"
        self.reports_dir = self.root / "reports"
        self.work_dir = self.root / "work"
        self.scan_output_dir = self.work_dir / "scan_output"
        self.staging_dir = self.work_dir / "live_lib_staging"
        self.download_dir = self.work_dir / "downloads"
        self.tools_dir = self.root / "tools"
        self.depcheck_dir = self.tools_dir / "dependency-check"
        self.template_file = self.config_dir / CONFIG_TEMPLATE_NAME

    # ------------------------------------------------------------------ #
    # config.txt
    # ------------------------------------------------------------------ #
    @property
    def legacy_config_file(self) -> Path:
        return self.root / CONFIG_FILE_NAME

    def find_config_file(self) -> Path:
        """config/config.txt, or ./config.txt from the pre-v2.3 flat layout.

        Having both is refused rather than guessed at: an in-place upgrade that
        silently picked the wrong one would run every scheduled scan with the
        wrong settings.
        """
        current = self.config_dir / CONFIG_FILE_NAME
        legacy = self.legacy_config_file
        if current.exists() and legacy.exists():
            raise ConfigLocationError(
                f"Two settings files found:\n    {current}\n    {legacy}\n"
                f"Keep your real settings in {current} and delete the other one.")
        if current.exists():
            return current
        if legacy.exists():
            print(f"NOTE: using {legacy} (older layout). It can be moved to {current} - "
                  f"relative paths inside it keep working either way.")
            return legacy
        return current

    def create_config_from_template(self) -> Path:
        """First run: copies config.template.txt to config/config.txt.

        The packages ship only the template, never a config.txt, so unpacking
        a new version over an existing install can never overwrite real
        settings.
        """
        target = self.config_dir / CONFIG_FILE_NAME
        if not self.template_file.exists():
            raise ConfigLocationError(
                f"No settings file at {target}, and no {CONFIG_TEMPLATE_NAME} next to it to start from.")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.template_file, target)
        return target

    def create_missing_starter_files(self) -> list:
        """app_list.txt / prompt_template.txt from their starting points in
        config/, where missing. Returns the files created."""
        created = []
        for name, starter in STARTER_FILES.items():
            target, source = self.config_dir / name, self.config_dir / starter
            if not target.exists() and source.exists():
                shutil.copyfile(source, target)
                created.append(target)
        return created

    # ------------------------------------------------------------------ #
    # Resolving paths written inside config.txt / app_list.txt
    # ------------------------------------------------------------------ #
    def resolve_setting(self, value: str, config_dir: Path = None) -> Path:
        """A file or folder path from config.txt: absolute as written; relative
        ones are tried next to config.txt, then in the project root. When
        neither exists yet (a cache file on its first run, say), it goes next
        to config.txt."""
        path = Path(value.strip())
        if path.is_absolute():
            return path
        base = Path(config_dir) if config_dir is not None else self.config_dir
        for candidate in (base / path, self.root / path):
            if candidate.exists():
                return candidate
        return base / path

    def resolve_app_folder(self, value: str) -> Path:
        """An application folder from APP_FOLDERS or app_list.txt: absolute as
        written; relative ones are looked up in apps/, then in the project
        root (the pre-v2.3 place for application folders)."""
        path = Path(value.strip())
        if path.is_absolute():
            return path
        for candidate in (self.apps_dir / path, self.root / path):
            if candidate.exists():
                return candidate
        return self.apps_dir / path
