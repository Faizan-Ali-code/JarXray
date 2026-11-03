"""
Command-line entry point - the same one for `python -m depcheck_automation`
and for the standalone run_dependency_check.exe (PyInstaller builds from this
file, which is why the imports are absolute, not relative).

    (no arguments)      interactive scan of every application
    --scheduled         unattended scan: no prompts (what the scheduled task runs)
    --setup-schedule    register/update the Windows Scheduled Task from config.txt
    --install-dependency-check [--reinstall] [--zip <file>]
                        download dependency-check into tools\\dependency-check
    --version           print the version and exit

Normally started through run_dependency_check.bat / setup_schedule.bat /
scripts\\setup_dependency_check.bat.
"""
import sys

from depcheck_automation import TOOL_VERSION

USAGE = __doc__.split("\n\n")[1]


def _line_buffered_output() -> None:
    # Redirected to a file (the scheduled-run log), Python buffers its output
    # in blocks while dependency-check writes straight to the same file - the
    # tool's own messages then land after dependency-check's, or are lost if
    # the run is killed. Line buffering keeps the log in order.
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(line_buffering=True)
            except (ValueError, OSError):
                pass


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    _line_buffered_output()
    if "--version" in argv:
        print(f"Dependency-Check Automation v{TOOL_VERSION}")
        return 0
    if "--help" in argv or "-h" in argv or "/?" in argv:
        print("Usage: run_dependency_check [--scheduled | --setup-schedule | --install-dependency-check | --version]\n")
        print(USAGE)
        return 0

    try:
        if "--setup-schedule" in argv:
            from depcheck_automation.scheduler import main as setup_schedule
            return setup_schedule()
        if "--install-dependency-check" in argv:
            from depcheck_automation.dc_install import main as install_dependency_check
            return install_dependency_check(argv)
        from depcheck_automation.cli import main as run_scan
        return run_scan(argv)
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
