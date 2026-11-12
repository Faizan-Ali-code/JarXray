"""Registers/updates a Windows Scheduled Task that runs this tool unattended,
on the cadence configured by the SCHEDULE_* keys in config.txt.

Windows Task Scheduler is what keeps the tool "running forever" - surviving
reboots, waking up at the configured cut-off time - rather than this process
staying alive in a loop of its own. Run this (via setup_schedule.bat) once
per machine, and again any time you change the SCHEDULE_* values.

The task is registered from an XML definition rather than schtasks' own
flags, because those cannot change the defaults that make a "daily" task
quietly skip days: a start missed while the PC was off or asleep is never
made up, and on battery power the task does not start at all.
"""
import os
import re
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape, unescape

from .config import flag, load_project_config
from .paths import ProjectPaths

TASK_NAME_DEFAULT = "DependencyCheckAutomation"
LAUNCHER_NAME = "run_dependency_check.bat"

VALID_FREQUENCIES = {"DAILY", "WEEKLY", "MONTHLY", "YEARLY"}
WEEKDAYS = {"MON": "Monday", "TUE": "Tuesday", "WED": "Wednesday", "THU": "Thursday",
            "FRI": "Friday", "SAT": "Saturday", "SUN": "Sunday"}
MONTHS = {"JAN": "January", "FEB": "February", "MAR": "March", "APR": "April", "MAY": "May",
          "JUN": "June", "JUL": "July", "AUG": "August", "SEP": "September", "OCT": "October",
          "NOV": "November", "DEC": "December"}
VALID_WEEKDAYS = set(WEEKDAYS)
VALID_MONTHS = set(MONTHS)
TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
SYSTEM_SID = "S-1-5-18"

# Longer than any real run (a full NVD refresh after weeks offline included),
# shorter than a day: a hung run is stopped before the next daily start,
# which would otherwise be skipped because the previous one is still running.
EXECUTION_TIME_LIMIT = "PT23H"


def _day_of_month(config: dict, key: str) -> str:
    day = config.get(key, "1").strip() or "1"
    if not day.isdigit() or not 1 <= int(day) <= 31:
        print(f"ERROR: {key} must be a day of the month from 1 to 31, got '{day}'.")
        sys.exit(1)
    return str(int(day))


def _run_time(config: dict) -> str:
    """SCHEDULE_TIME as HH:MM (24-hour)."""
    value = config.get("SCHEDULE_TIME", "22:00").strip() or "22:00"
    match = TIME_RE.match(value)
    if not match:
        print(f"ERROR: SCHEDULE_TIME must be a 24-hour time like 22:00 or 06:30, got '{value}'.")
        sys.exit(1)
    return f"{int(match.group(1)):02d}:{match.group(2)}"


def task_name_from(config: dict) -> str:
    return config.get("SCHEDULE_TASK_NAME", TASK_NAME_DEFAULT).strip() or TASK_NAME_DEFAULT


def _schedule(config: dict, run_time: str) -> tuple:
    """(Task Scheduler <Schedule...> element, plain-English description)."""
    frequency = config.get("SCHEDULE_FREQUENCY", "DAILY").strip().upper()
    if frequency not in VALID_FREQUENCIES:
        print(f"ERROR: SCHEDULE_FREQUENCY must be one of {sorted(VALID_FREQUENCIES)}, got '{frequency}'.")
        sys.exit(1)

    if frequency == "DAILY":
        return "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>", f"every day at {run_time}"

    if frequency == "WEEKLY":
        weekday = config.get("SCHEDULE_WEEKLY_DAY", "MON").strip().upper() or "MON"
        if weekday not in VALID_WEEKDAYS:
            print(f"ERROR: SCHEDULE_WEEKLY_DAY must be one of {sorted(VALID_WEEKDAYS)}, got '{weekday}'.")
            sys.exit(1)
        return (f"<ScheduleByWeek><DaysOfWeek><{WEEKDAYS[weekday]} /></DaysOfWeek>"
                f"<WeeksInterval>1</WeeksInterval></ScheduleByWeek>",
                f"every {WEEKDAYS[weekday]} at {run_time}")

    if frequency == "MONTHLY":
        day, months = _day_of_month(config, "SCHEDULE_MONTHLY_DAY"), list(MONTHS.values())
        when = f"on day {day} of every month at {run_time}"
    else:
        # Task Scheduler has no yearly schedule either: a monthly one limited
        # to a single month fires once a year.
        month = config.get("SCHEDULE_YEARLY_MONTH", "JAN").strip().upper() or "JAN"
        if month not in VALID_MONTHS:
            print(f"ERROR: SCHEDULE_YEARLY_MONTH must be one of {sorted(VALID_MONTHS)}, got '{month}'.")
            sys.exit(1)
        day, months = _day_of_month(config, "SCHEDULE_YEARLY_DAY"), [MONTHS[month]]
        when = f"every year on {MONTHS[month]} {day} at {run_time}"
    return (f"<ScheduleByMonth><DaysOfMonth><Day>{day}</Day></DaysOfMonth><Months>"
            + "".join(f"<{m} />" for m in months) + "</Months></ScheduleByMonth>", when)


def _current_user() -> str:
    user = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    return f"{domain}\\{user}" if domain and user else user


def build_task_xml(config: dict, script_dir: Path) -> tuple:
    """(task definition XML, task name, plain-English schedule description)."""
    task_name = task_name_from(config)
    run_time = _run_time(config)
    schedule, when = _schedule(config, run_time)

    bat_path = Path(script_dir) / LAUNCHER_NAME
    if not bat_path.exists():
        print(f"ERROR: {bat_path} not found - run this from the tool's folder.")
        sys.exit(1)

    if flag(config, "SCHEDULE_RUN_AS_SYSTEM"):
        # Runs whether or not anyone is logged on (needs an administrator to register).
        principal = f"<UserId>{SYSTEM_SID}</UserId><RunLevel>HighestAvailable</RunLevel>"
        when += ", as SYSTEM (also when nobody is logged on)"
    else:
        principal = (f"<UserId>{escape(_current_user())}</UserId><LogonType>InteractiveToken</LogonType>"
                     f"<RunLevel>LeastPrivilege</RunLevel>")
        when += f", as {_current_user()} (while that user is logged on, also when locked)"

    # The start boundary only anchors the time of day; a date in the past is
    # fine and does not make the task run on registration.
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{escape(f"JarXray: unattended scan of the applications in {script_dir}. Created by setup_schedule.bat from config.txt - change it there, not here.")}</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{date.today():%Y-%m-%d}T{run_time}:00</StartBoundary>
      <Enabled>true</Enabled>
      {schedule}
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">{principal}</Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>{EXECUTION_TIME_LIMIT}</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(f'"{bat_path}"')}</Command>
      <Arguments>--scheduled</Arguments>
      <WorkingDirectory>{escape(str(Path(script_dir)))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""
    return xml, task_name, when


def _schtasks(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["schtasks", *args], capture_output=True, text=True)


# --------------------------------------------------------------------------- #
# SCHEDULE_RUN_AS_SYSTEM: the task runs code from these folders as SYSTEM.
# Anyone who can change a file there (the .bat, the Python package, python.exe
# itself) could make SYSTEM run their code: a local privilege escalation.
# --------------------------------------------------------------------------- #
WRITE_RIGHTS = {"F", "M", "W", "WD", "AD", "GA", "GW", "WDAC", "WO", "DC"}
TRUSTED_PRINCIPALS = {"NT AUTHORITY\\SYSTEM", "SYSTEM", "BUILTIN\\ADMINISTRATORS", "ADMINISTRATORS",
                      "NT SERVICE\\TRUSTEDINSTALLER", "CREATOR OWNER"}


def writable_principals(icacls_output: str, path: str) -> list:
    """Accounts other than SYSTEM / Administrators that icacls shows with a write right on `path`
    (also inherit-only entries: they apply to the files inside). Names are as icacls prints them;
    on a non-English Windows, built-in names are translated and show up here to be checked by hand."""
    found = set()
    for line in (icacls_output or "").splitlines():
        text = line.strip()
        if text.lower().startswith(str(path).lower()):
            text = text[len(str(path)):].strip()
        match = re.match(r"^(.+?):((?:\([^)]*\))+)$", text)
        if not match:
            continue
        principal = match.group(1).strip()
        rights = {r.strip() for group in re.findall(r"\(([^)]*)\)", match.group(2)) for r in group.split(",")}
        if rights & WRITE_RIGHTS and principal.upper() not in TRUSTED_PRINCIPALS:
            found.add(principal)
    return sorted(found)


def _icacls(path: Path):
    try:
        result = subprocess.run(["icacls", str(path)], capture_output=True, text=True)
    except OSError:
        return None  # not Windows
    return result.stdout if result.returncode == 0 else None


def python_home(root: Path) -> Path:
    """The Python installation the scheduled task's .venv runs (its pyvenv.cfg 'home'), else this one."""
    for venv in ("virtual", "venv", ".venv"):
        cfg = Path(root) / venv / "pyvenv.cfg"
        if cfg.is_file():
            for line in cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
                key, _, value = line.partition("=")
                if key.strip().lower() == "home" and value.strip():
                    return Path(value.strip())
    return Path(sys.executable).parent


def system_task_folders_problems(root: Path, icacls=_icacls) -> list:
    """[(folder, [accounts that can write to it])] for the folders a SYSTEM task would run code from."""
    problems = []
    for folder in dict.fromkeys([Path(root), python_home(root)]):
        output = icacls(folder)
        if output is None:
            print(f"  WARNING: could not read the permissions of {folder} - check by hand that only "
                  f"administrators can change it.")
            continue
        accounts = writable_principals(output, str(folder))
        if accounts:
            problems.append((folder, accounts))
    return problems


def existing_task_command(task_name: str):
    """The program an already registered task of this name runs, or None if
    there is no such task."""
    result = _schtasks("/query", "/tn", task_name, "/xml", "ONE")
    if result.returncode != 0:
        return None
    match = re.search(r"<Command>(.*?)</Command>", result.stdout or "", re.DOTALL)
    return unescape(match.group(1)).strip().strip('"') if match else ""


def _same_file(a: str, b: Path) -> bool:
    return os.path.normcase(os.path.normpath(a)) == os.path.normcase(os.path.normpath(str(b)))


def _next_run_time(task_name: str) -> str:
    result = _schtasks("/query", "/tn", task_name, "/fo", "LIST")
    for line in (result.stdout or "").splitlines():
        if line.lower().startswith("next run time"):
            return line.split(":", 1)[1].strip()
    return ""


def _remove_own_task(task_name: str, bat_path: Path) -> int:
    command = existing_task_command(task_name)
    if command is None:
        print("SCHEDULE_ENABLED is not 'yes' and no task is registered - nothing to do.")
        print("Set SCHEDULE_ENABLED=yes and the other SCHEDULE_* keys, then run this again.")
        return 0
    if not _same_file(command, bat_path):
        print(f"SCHEDULE_ENABLED is not 'yes' - nothing to do. (A task named '{task_name}' exists, "
              f"but it runs another copy of the tool and is left alone: {command})")
        return 0
    result = _schtasks("/delete", "/tn", task_name, "/f")
    if result.returncode != 0:
        print((result.stderr or result.stdout).strip())
        print(f"\nERROR: could not remove the scheduled task '{task_name}' (exit {result.returncode}).")
        return result.returncode
    print(f"SCHEDULE_ENABLED is not 'yes', so the scheduled task '{task_name}' was removed.")
    print("Set SCHEDULE_ENABLED=yes and run this again to bring it back.")
    return 0


def main(root: Path = None) -> int:
    paths = ProjectPaths(root)

    print("=" * 70)
    print(" JarXray - Scheduled Task Setup")
    print("=" * 70)

    config, config_file = load_project_config(paths)
    task_name = task_name_from(config)
    bat_path = paths.root / LAUNCHER_NAME

    if not flag(config, "SCHEDULE_ENABLED"):
        print(f"Settings: {config_file}")
        return _remove_own_task(task_name, bat_path)

    xml, task_name, when = build_task_xml(config, paths.root)

    if flag(config, "SCHEDULE_RUN_AS_SYSTEM"):
        problems = system_task_folders_problems(paths.root)
        for folder, accounts in problems:
            print(f"ERROR: {', '.join(accounts)} can change files in {folder}.")
        if problems and not flag(config, "SCHEDULE_ALLOW_WRITABLE_FOLDERS"):
            print("\nA task running as SYSTEM would run code that these accounts can replace, which would let them")
            print("run their own code as SYSTEM. Before registering it:")
            print("  - put the tool in a folder only administrators can change (e.g. under C:\\Program Files),")
            print("  - use a Python installed for all users (e.g. C:\\Program Files\\Python312), then run")
            print("    scripts\\setup_venv.bat --recreate,")
            print("  or set SCHEDULE_RUN_AS_SYSTEM=no to run the task as your own account instead.")
            print("(SCHEDULE_ALLOW_WRITABLE_FOLDERS=yes overrides this check - only for a machine where those")
            print("accounts are administrators anyway.)")
            return 1

    # Two copies of the tool (QA and PROD, say) left on the same task name
    # would keep replacing each other's task - refuse instead.
    command = existing_task_command(task_name)
    if command and not _same_file(command, bat_path):
        print(f"ERROR: a scheduled task named '{task_name}' already runs another copy of the tool:")
        print(f"    {command}")
        print(f"Give this copy its own SCHEDULE_TASK_NAME in {config_file} and run this again.")
        return 1

    print(f"Registering Windows Scheduled Task '{task_name}': {when}")
    # schtasks wants the definition as a UTF-16 file.
    fd, xml_file = tempfile.mkstemp(prefix="depcheck_task_", suffix=".xml")
    os.close(fd)
    try:
        Path(xml_file).write_text(xml, encoding="utf-16")
        result = _schtasks("/create", "/f", "/tn", task_name, "/xml", xml_file)
    finally:
        os.unlink(xml_file)

    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0:
        print(result.stderr.strip())
        if "denied" in (result.stderr or "").lower() and flag(config, "SCHEDULE_RUN_AS_SYSTEM"):
            print("\nSCHEDULE_RUN_AS_SYSTEM=yes needs an administrator: right-click setup_schedule.bat >")
            print("'Run as administrator' (or set SCHEDULE_RUN_AS_SYSTEM=no).")
        print(f"\nERROR: schtasks failed (exit {result.returncode}). See output above.")
        return result.returncode

    print(f"\nTask '{task_name}' registered/updated successfully.")
    next_run = _next_run_time(task_name)
    if next_run:
        print(f"Next run: {next_run}")
    print(f"It runs {bat_path} --scheduled unattended;")
    print("a start missed while this PC was off or asleep runs as soon as it is back.")
    print(f"Each run's output is appended to {paths.reports_dir / '_logs' / 'scheduled_runs.log'}")
    print(f"Run it once right now to test:  schtasks /run /tn \"{task_name}\"")
    print("Change the schedule in config.txt and run setup_schedule.bat again; set")
    print("SCHEDULE_ENABLED=no and run it again to remove the task.")
    return 0
