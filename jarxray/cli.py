"""Orchestration: prompts, per-application pipeline, final summary."""
import os
import shutil
import sys
import traceback
from datetime import datetime
from pathlib import Path

from . import TOOL_VERSION
from .ai_lookup import add_ai_notes
from .config import check_required_packages, flag, load_project_config
from .dc_json import count_total_dependencies, parse_dependency_check_json, read_analysis_exceptions
from .emailer import send_report_email
from .fix_lookup import apply_fix_lookup
from .jar_classifier import internal_prefixes, is_inside, resolve_app_folders, separate_jars, stage_copy_of_folder
from .naming import build_analysis_filename, build_report_filename, sanitize_for_filename
from .paths import ProjectPaths
from .report_html import build_risk_html_report
from .report_ods import build_ods_report
from .scanner import run_dependency_check

# The names dependency-check always uses inside --out. Picked by exact name:
# with OUTPUT_FORMAT=ALL the folder also holds e.g. dependency-check-jenkins.html
# and dependency-check-gitlab.json, which are NOT the report to build from.
DC_HTML = "dependency-check-report.html"
DC_JSON = "dependency-check-report.json"


def derive_app_code(folder_name: str) -> str:
    """Fallback Application Code for unattended/scheduled runs: the folder
    name with non-alphanumeric characters stripped, uppercased."""
    code = "".join(ch for ch in folder_name.upper() if ch.isalnum())
    return code[:20] or "APP"


def prompt_with_default(label: str, default_value: str) -> str:
    suffix = f" [{default_value}]" if default_value else ""
    value = input(f"{label}{suffix}: ").strip()
    return value or default_value


def unique_report_path(path: Path) -> Path:
    """
    Report filenames carry the date but not the time, so a second run of the
    same application on the same day (a manual re-run alongside the scheduled
    one, say) would land on the exact same name. Appends a time suffix instead
    of overwriting the earlier run's report.
    """
    if not path.exists():
        return path
    stamp = datetime.now().strftime("%H%M%S")
    candidate, attempt = path.with_name(f"{path.stem}-{stamp}{path.suffix}"), 2
    while candidate.exists():
        candidate = path.with_name(f"{path.stem}-{stamp}-{attempt}{path.suffix}")
        attempt += 1
    return candidate


def _keep_extra_outputs(config: dict, temp_out_dir: Path, reports_dir: Path, results: dict,
                        project_name: str, app_code: str, environment: str) -> None:
    """Moves any other format the user asked for (CSV, XML, SARIF, ...) into
    the reports folder under the standard naming, instead of deleting it with
    the temp folder. The JSON is only kept if it was asked for explicitly."""
    requested = {f.strip().upper() for f in config.get("OUTPUT_FORMAT", "").split(",")}
    keep_json = bool(requested & {"JSON", "ALL"})
    for extra in sorted(p for p in temp_out_dir.iterdir() if p.is_file()):
        if extra.name == DC_JSON and not keep_json:
            continue
        stem, _, ext = extra.name.partition(".")
        target = unique_report_path(reports_dir / build_analysis_filename(
            project_name, app_code, environment, stem, ext or "out"))
        shutil.move(str(extra), str(target))
        results[extra.name] = target


def finalize_all_reports(config: dict, script_dir: Path, temp_out_dir: Path, reports_dir: Path,
                           project_name: str, app_code: str, environment: str) -> dict:
    """
    Moves/renames the raw dependency-check HTML report, then (if a JSON report
    is present) parses it, looks up the fixed versions in OSV / Maven Central
    (which also confirms or questions each CVE), adds AI notes (if enabled),
    and builds the ODS analysis sheet + the dependency risk report. Cleans up
    the temp folder last. Returns a dict of the final paths produced (missing
    keys if that step could not run, e.g. no JSON found).
    """
    results = {}
    reports_dir.mkdir(parents=True, exist_ok=True)

    # --- Raw dependency-check HTML report ---
    html_src = temp_out_dir / DC_HTML
    if html_src.is_file():
        final_path = unique_report_path(
            reports_dir / build_report_filename(project_name, app_code, environment))
        shutil.move(str(html_src), str(final_path))
        results["dependency_check_html"] = final_path
    else:
        print(f"  WARNING: no {DC_HTML} in the output folder - check OUTPUT_FORMAT/EXTRA_ARGS in config.txt")

    # --- Parse JSON -> fixed versions (OSV) -> AI notes -> ODS + risk report ---
    json_src = temp_out_dir / DC_JSON
    if not json_src.is_file():
        print(f"  WARNING: no {DC_JSON} found - skipping the analysis sheet and risk report for this application.")
    else:
        dependencies = parse_dependency_check_json(json_src, internal_prefixes(config))
        total_scanned = count_total_dependencies(json_src)
        affected = sum(1 + len(d["related_files"]) for d in dependencies)
        print(f"  {len(dependencies)} vulnerable dependencies ({affected} jar files incl. related) "
              f"of {total_scanned} files scanned.")

        triage = apply_fix_lookup(config, ProjectPaths(script_dir).work_dir / "cache", dependencies)
        if triage["looked_up"]:
            print(f"  OSV confirms {triage['confirmed']} CVE finding(s); {triage['unconfirmed']} not listed by OSV "
                  f"(possible false positives); {triage['unknown']} not checked.")
        add_ai_notes(config, script_dir, dependencies)

        ods_path = unique_report_path(reports_dir / build_analysis_filename(
            project_name, app_code, environment, "dependency-check-analysis", "ods"))
        build_ods_report(dependencies, ods_path, project_name, app_code, environment)
        results["ods_report"] = ods_path

        risk_path = unique_report_path(reports_dir / build_analysis_filename(
            project_name, app_code, environment, "dependency-risk-report", "html"))
        build_risk_html_report(dependencies, risk_path, project_name, app_code, environment, total_scanned, triage)
        results["risk_html"] = risk_path

    _keep_extra_outputs(config, temp_out_dir, reports_dir, results, project_name, app_code, environment)
    shutil.rmtree(temp_out_dir, ignore_errors=True)
    return results


def scan_output_usable(return_code: int, temp_out_dir: Path) -> bool:
    """dependency-check exits 14 (13 if fatal) when an analyzer hit an error -
    e.g. its .NET analyzer on a machine without the dotnet runtime - AFTER it
    has written complete reports, and 1 for --failOnCVSS. A non-zero code
    with both reports present is a finished scan, not a failed one."""
    if return_code == 0:
        return True
    if (temp_out_dir / DC_JSON).is_file() and (temp_out_dir / DC_HTML).is_file():
        print(f"  NOTE: dependency-check exited with code {return_code} but wrote complete reports - using them.")
        for message in read_analysis_exceptions(temp_out_dir / DC_JSON):
            print(f"    dependency-check reported: {message}")
        return True
    print(f"  dependency-check.bat exited with code {return_code}. "
          f"Check the output above. Raw output left at: {temp_out_dir}")
    return False


def _identify(display_name: str, config: dict, scheduled: bool, state: dict) -> tuple:
    if scheduled:
        project_name = display_name
        configured_app_code = config.get("SCHEDULE_APP_CODE", "AUTO").strip()
        app_code = configured_app_code if configured_app_code and configured_app_code.upper() != "AUTO" \
            else derive_app_code(display_name)
        environment = state["environment"]
        print(f"Project Name: {project_name} | Application Code: {app_code} | Environment: {environment}")
    else:
        project_name = prompt_with_default("Project Name", display_name)
        app_code = prompt_with_default("Application Code", state["app_code"])
        environment = prompt_with_default("Environment", state["environment"])
    state.update(app_code=app_code, environment=environment)
    return project_name, app_code, environment


def process_application(app_folder, config: dict, paths: ProjectPaths, scheduled: bool, state: dict) -> tuple:
    """Runs one application through the pipeline.
    Returns (status, project_name, result_paths), status being ok/skipped/failed."""
    display_name, app_dir = app_folder.name, app_folder.path
    # LIST_FILE mode lets the app name be anything the user typed in
    # app_list.txt, and it gets used as a folder name below - so a name
    # like "Payments/Core" would otherwise silently create a nested
    # folder (or fail outright on a character Windows rejects).
    path_safe_name = sanitize_for_filename(display_name)
    # STAGING moves the internal jars aside inside the folder itself, which is
    # only safe in a folder the tool owns. A folder outside the tool's own
    # folder is, as often as not, a deployed application's real lib folder,
    # where moving its internal jars would break the application's next
    # start - so it is always copied first, whatever SCAN_MODE says.
    live_lib = config.get("SCAN_MODE") == "LIVE_LIB" or not is_inside(app_dir, paths.root)
    print("\n" + "-" * 70)
    print(f" Application: {display_name} ({app_dir})")
    print("-" * 70)

    working_dir = app_dir
    if live_lib:
        working_dir = stage_copy_of_folder(app_dir, paths.staging_dir, path_safe_name)
        print(f"Copied the jars to a temporary folder (the original folder is never changed): {working_dir}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    nested_dir = paths.work_dir / "nested_libs" / f"{path_safe_name}_{timestamp}"
    try:
        sep = separate_jars(working_dir, internal_prefixes(config), nested_dir)

        if sep.moved:
            print(f"Moved {sep.moved} internal jar(s) to: {sep.internal_dir}")
        else:
            print("No internal jars found (nothing moved).")
        if sep.nested_extracted:
            print(f"Unpacked {len(sep.nested_extracted)} third-party librar(y/ies) bundled in internal archives "
                  f"(fat jar / WAR); they are scanned from: {nested_dir}")
        if sep.kept_shaded:
            print(f"Kept {len(sep.kept_shaded)} internal jar(s) in the scan because they contain shaded "
                  f"third-party code (their own coordinates are left out of the report):")
            for j in sep.kept_shaded:
                print(f"    - {j.relative_to(working_dir)}")

        if sep.leftover_internal:
            # separate_jars already retried these - something (e.g. a file lock
            # held by another process) keeps them from moving.
            print(f"  WARNING: {len(sep.leftover_internal)} internal jar(s) could not be moved (file locked?):")
            for j in sep.leftover_internal:
                print(f"    - {j.relative_to(working_dir)}")
            print("  They are excluded from the scan by name; please check file locks/permissions.")

        print(f"{sep.remaining} jar(s) remain in '{working_dir.name}' for scanning.")
        if sep.to_scan <= 0:
            print(f"Nothing to scan for {display_name} - skipping dependency-check.")
            return "skipped", display_name, None

        project_name, app_code, environment = _identify(display_name, config, scheduled, state)

        temp_out_dir = paths.scan_output_dir / f"{path_safe_name}_{timestamp}"
        scan_dirs = [working_dir] + ([nested_dir] if sep.nested_extracted else [])
        return_code = run_dependency_check(config, scan_dirs, project_name, temp_out_dir,
                                           exclude_names=[j.name for j in sep.leftover_internal])
    finally:
        # Also on Ctrl+C or an error: a leaked copy is a full copy of a lib folder.
        if live_lib:
            shutil.rmtree(working_dir, ignore_errors=True)
        shutil.rmtree(nested_dir, ignore_errors=True)

    if not scan_output_usable(return_code, temp_out_dir):
        return "failed", project_name, None

    # Each application's reports live in their own subfolder under reports/,
    # named after the application, so results from different applications never
    # mix together in one flat listing.
    result_paths = finalize_all_reports(config, paths.root, temp_out_dir, paths.reports_dir / path_safe_name,
                                        project_name, app_code, environment)
    for label, path in result_paths.items():
        print(f"  {label}: {path}")
    if not result_paths:
        return "failed", project_name, None

    send_report_email(config, project_name, app_code, environment, result_paths)
    return "ok", project_name, result_paths


def prune_old_reports(reports_dir: Path, config: dict) -> int:
    """REPORTS_KEEP_DAYS: deletes report files older than that many days from
    reports/<app>/ and returns how many. Only files named the way this tool
    names its reports ("[date][Project]...") - never logs, never anything
    someone put there by hand. Anything but a whole number >= 0 deletes
    nothing: a typo must not cost anyone their reports."""
    raw = (config.get("REPORTS_KEEP_DAYS") or "0").strip()
    if not raw.isdigit():
        print(f"WARNING: REPORTS_KEEP_DAYS={raw!r} is not a number of days - no old reports deleted.")
        return 0
    days = int(raw)
    if days == 0 or not reports_dir.is_dir():
        return 0
    cutoff = datetime.now().timestamp() - days * 86400
    removed = 0
    for app_dir in reports_dir.iterdir():
        if not app_dir.is_dir() or app_dir.name.startswith("_"):
            continue
        for report in app_dir.iterdir():
            if report.is_file() and report.name.startswith("[") and report.stat().st_mtime < cutoff:
                try:
                    report.unlink()
                    removed += 1
                except OSError as exc:  # open in Excel/LibreOffice, say
                    print(f"  WARNING: could not delete old report {report.name} ({exc}).")
    if removed:
        print(f"\nREPORTS_KEEP_DAYS={days}: deleted {removed} report file(s) older than {days} days.")
    return removed


def _explain_no_apps(paths: ProjectPaths, mode: str, listed: bool) -> None:
    print("\nNo application folders with jars found.")
    if mode == "LIST" or (listed and mode == "AUTO"):
        print("Check the APP_FOLDERS / APP_LIST_FILE paths in config.txt - see warnings above.")
    elif mode == "LIST_FILE":
        print("Check the entries in the APP_LIST_FILE list - see warnings above.")
    else:
        paths.apps_dir.mkdir(parents=True, exist_ok=True)
        print("Either list each application's lib folder in config.txt, for example:")
        print("    APP_FOLDERS=D:\\QA\\OrderService\\lib, D:\\QA\\BillingApi\\lib")
        print("or create one folder per application inside:")
        print(f"    {paths.apps_dir}")
        print("and put that application's jars in it (e.g. apps\\BillingApi\\*.jar),")
        print("then run this again.")


def main(argv=None, root: Path = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    scheduled = "--scheduled" in argv
    paths = ProjectPaths(root)

    print("=" * 70)
    print(f" JarXray (v{TOOL_VERSION})   {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 70)
    print(f"Python interpreter: {sys.executable}")
    if scheduled:
        print("Mode: SCHEDULED / unattended run - no interactive prompts, using config.txt defaults.")

    check_required_packages(need_openai=False)  # odfpy is always required, regardless of config

    config, config_file = load_project_config(paths)
    check_required_packages(need_openai=flag(config, "ENABLE_AI"))

    mode = config["MODE"]
    print(f"\nSettings: {config_file}")
    print(f"Mode: {mode}")
    if config["SCAN_MODE"] == "LIVE_LIB":
        print("Scan mode: LIVE_LIB - jars will be COPIED to a temp staging folder before "
              "separation/scanning; configured app folders are never modified.")
    prefixes = internal_prefixes(config)
    if prefixes:
        print(f"Internal packages (their jars are set aside; third-party libraries inside them are still "
              f"scanned): {', '.join(prefixes)}")
    else:
        print("INTERNAL_PACKAGES is empty - no jars are set aside; every jar is scanned.")

    # Listed folders that can't be scanned (missing, no jars) fail the run, so
    # Task Scheduler's "Last Run Result" shows it instead of only the log.
    problems = []
    app_folders = resolve_app_folders(paths, config, problems)
    if not app_folders:
        _explain_no_apps(paths, mode, listed=bool(problems))
        return 1

    print(f"Found {len(app_folders)} application folder(s) to process:")
    for app_folder in app_folders:
        print(f"  - {app_folder.name}: {app_folder.path}")

    state = {"app_code": "", "environment": config.get("DEFAULT_ENVIRONMENT", "")}
    summary = []
    for app_folder in app_folders:
        try:
            status, project_name, result_paths = process_application(app_folder, config, paths, scheduled, state)
        except EOFError:
            print("\nERROR: no console input available for the prompts - use --scheduled for unattended runs.")
            return 1
        except Exception:
            # One broken application must not cost every application after it
            # its scan (and, in a scheduled run, its email).
            traceback.print_exc()
            print(f"  ERROR: {app_folder.name} failed with the error above - continuing with the next application.")
            status, project_name, result_paths = "failed", app_folder.name, None
        summary.append((app_folder.name, project_name, status, result_paths))

    print("\n" + "=" * 70)
    print(" Summary")
    print("=" * 70)
    for folder_name, project_name, status, result_paths in summary:
        if status == "ok":
            print(f"  {folder_name} ({project_name}):")
            for label, path in result_paths.items():
                print(f"    {label}: {path}")
        elif status == "skipped":
            print(f"  {folder_name}: skipped - no third-party jars to scan")
        else:
            print(f"  {folder_name} ({project_name}): FAILED - see output above")
    for name, reason in problems:
        print(f"  {name}: NOT SCANNED - {reason}")

    prune_old_reports(paths.reports_dir, config)

    if not scheduled and flag(config, "AUTO_OPEN_REPORT"):
        for _, _, status, result_paths in summary:
            for path in (result_paths or {}).values():
                try:
                    os.startfile(path)  # Windows-only
                except (AttributeError, OSError):
                    pass

    failed = [name for name, _, status, _ in summary if status == "failed"] + [name for name, _ in problems]
    if failed:
        print(f"\n{len(failed)} of {len(summary) + len(problems)} application(s) FAILED or NOT SCANNED: "
              f"{', '.join(failed)}")
        return 1
    return 0
