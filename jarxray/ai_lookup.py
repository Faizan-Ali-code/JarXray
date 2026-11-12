"""Optional AI migration note per vulnerable dependency (ENABLE_AI=yes).

The AI no longer decides anything that goes into "Recommended Version" or
"Status": those come from OSV and Maven Central (fix_lookup.py). The model is
only asked for a one-sentence migration note about the upgrade that was
already chosen (e.g. "needs Java 17", "artifact moved to ...httpcore5"),
which the reports show labelled "AI note (unverified)".

Answers are cached in AI_CACHE_FILE for AI_CACHE_DAYS (default 30) per
groupId:artifactId:version -> recommended version, so a daily run does not
pay for the same question again, and stale notes are refreshed.
"""
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from .config import flag

AI_NOTE_PREFIX = "AI note (unverified): "

# Comments the tool itself writes when there is no real AI answer. Entries
# like these are never cached, and ones already in an older cache are retried.
FAILURE_PREFIXES = ("AI lookup failed", "AI lookup skipped", "AI response could not be parsed")
PLACEHOLDER_COMMENT_PREFIXES = FAILURE_PREFIXES + ("AI lookup disabled",)

UNKNOWN_GROUP_TEXT = "(groupId unknown - identify it from the jar file name)"

_BUILT_IN_TEMPLATE = (
    "You are a Java dependency upgrade assistant. A vulnerable library is being upgraded; the target "
    "version was already chosen from OSV advisories and Maven Central - do not change it.\n\n"
    "Artifact: {{GROUP_ID}}:{{ARTIFACT_ID}}\n"
    "Jar file: {{FILE_NAME}}\n"
    "Current version: {{VERSION}}\n"
    "Upgrade target: {{RECOMMENDED_VERSION}} ({{STATUS}})\n"
    "Known vulnerabilities:\n{{CVE_SUMMARY}}\n\n"
    "In ONE sentence, note what a developer must watch for when making this upgrade (breaking API changes, "
    "a newer Java requirement, a renamed or relocated artifact). If nothing notable, answer with an empty "
    "string.\n\n"
    'Respond with ONLY a JSON object: {"comments": "..."}'
)


# --------------------------------------------------------------------------- #
# The cache (AI_CACHE_FILE)
# --------------------------------------------------------------------------- #
def _read_cache(cache_path: Path) -> tuple:
    """(cache, safe_to_save). An unreadable file is kept aside rather than overwritten."""
    if not cache_path.exists():
        return {}, True
    try:
        text = cache_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        print(f"  WARNING: could not read {cache_path.name} ({exc}) - AI answers from this run won't be cached.")
        return {}, False
    try:
        cache = json.loads(text)
        if not isinstance(cache, dict):
            raise ValueError("top level is not a JSON object")
        return cache, True
    except ValueError as exc:
        backup = cache_path.with_name(f"{cache_path.stem}.corrupt-{datetime.now():%Y%m%d-%H%M%S}{cache_path.suffix}")
        try:
            os.replace(cache_path, backup)
        except OSError:
            print(f"  WARNING: could not read {cache_path.name} ({exc}) and could not set it aside - "
                  f"AI answers from this run won't be cached.")
            return {}, False
        print(f"  WARNING: could not read {cache_path.name} ({exc}) - starting with an empty cache; "
              f"the unreadable file was kept as {backup.name}.")
        return {}, True


def load_ai_cache(cache_path: Path) -> dict:
    return _read_cache(Path(cache_path))[0]


def save_ai_cache(cache_path: Path, cache: dict) -> None:
    """Written to a temp file first, so an interrupted save can't truncate the cache."""
    cache_path = Path(cache_path)
    tmp = cache_path.with_name(cache_path.name + ".tmp")
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
        os.replace(tmp, cache_path)
    except OSError as e:
        print(f"  WARNING: could not save {cache_path.name}: {e}")


def _cache_key(dep: dict) -> str:
    return f"{dep['group_id'] or 'unknown'}:{dep['artifact_id']}:{dep['version']}->{dep.get('recommended_version')}"


def _fresh(entry, max_age_days: float, now: datetime) -> bool:
    if not isinstance(entry, dict) or "comments" not in entry or str(entry["comments"]).startswith(FAILURE_PREFIXES):
        return False
    try:
        cached_at = datetime.fromisoformat(entry.get("cached_at", ""))
    except ValueError:
        return False  # entries from older versions carry no date: ask again
    return now - cached_at < timedelta(days=max_age_days)


# --------------------------------------------------------------------------- #
# The OpenAI call
# --------------------------------------------------------------------------- #
def _extract_json_object(text: str) -> dict:
    """The first {...} JSON object in a model response, tolerating code fences or prose around it."""
    match = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def load_prompt_template(script_dir: Path, config: dict) -> str:
    prompt_file = config.get("AI_PROMPT_FILE", "prompt_template.txt").strip() or "prompt_template.txt"
    prompt_path = Path(script_dir) / prompt_file
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8-sig")
    print(f"  WARNING: AI_PROMPT_FILE not found ({prompt_path}) - using the built-in prompt instead.")
    return _BUILT_IN_TEMPLATE


def build_cve_summary(vulnerabilities: list) -> str:
    lines = []
    for v in vulnerabilities:
        score = v["cvss_score"] if v["cvss_score"] is not None else "n/a"
        version = f" {v['cvss_version']}" if v.get("cvss_version") else ""
        desc = (v["description"] or "")[:300]
        lines.append(f"- {v['cve_id']} ({v['severity']}, CVSS{version} {score}): {desc}")
    return "\n".join(lines)


def ask_ai_for_note(config: dict, dep: dict, template: str, client=None) -> str:
    """The model's one-sentence note, or a FAILURE_PREFIXES message."""
    if client is None:
        try:
            from openai import OpenAI
        except ImportError:
            return "AI lookup skipped: 'openai' package not installed (see scripts\\setup_venv.bat)"
        client = OpenAI(api_key=config["OPENAI_API_KEY"])
    prompt = (template
              .replace("{{GROUP_ID}}", dep["group_id"] or UNKNOWN_GROUP_TEXT)
              .replace("{{ARTIFACT_ID}}", dep["artifact_id"])
              .replace("{{FILE_NAME}}", dep.get("file_name") or f"{dep['artifact_id']}-{dep['version']}.jar")
              .replace("{{VERSION}}", dep["version"])
              .replace("{{RECOMMENDED_VERSION}}", str(dep.get("recommended_version") or "NA"))
              .replace("{{STATUS}}", str(dep.get("status") or ""))
              .replace("{{CVE_SUMMARY}}", build_cve_summary(dep["vulnerabilities"])))
    kwargs = {"model": config.get("OPENAI_MODEL", "gpt-4o").strip(), "input": prompt}
    if flag(config, "AI_USE_WEB_SEARCH", "yes"):
        kwargs["tools"] = [{"type": "web_search_preview"}]
    try:
        text = client.responses.create(**kwargs).output_text
    except Exception as e:  # network, key, quota, API changes: one dependency must not stop the run
        return f"AI lookup failed: {e}"
    parsed = _extract_json_object(text)
    if "comments" not in parsed:
        return "AI response could not be parsed as JSON"
    return str(parsed.get("comments") or "").strip()


def add_ai_notes(config: dict, script_dir: Path, dependencies: list, client=None, now: datetime = None) -> None:
    """Appends "AI note (unverified): ..." to each dependency's comments when ENABLE_AI=yes."""
    if not flag(config, "ENABLE_AI") or not dependencies:
        return
    now = now or datetime.now()
    try:
        max_age = float(config.get("AI_CACHE_DAYS") or 30)
    except ValueError:
        max_age = 30
    cache_path = Path(script_dir) / (config.get("AI_CACHE_FILE", "").strip() or "ai_recommendation_cache.json")
    cache, writable = _read_cache(cache_path)
    template = load_prompt_template(script_dir, config)
    dirty = False
    for dep in dependencies:
        key = _cache_key(dep)
        if _fresh(cache.get(key), max_age, now):
            note = cache[key]["comments"]
        else:
            print(f"    Asking AI for a migration note on {key} ...")
            note = ask_ai_for_note(config, dep, template, client)
            if note.startswith(FAILURE_PREFIXES):
                cache.pop(key, None)  # shown this run, asked again next run
            else:
                cache[key] = {"comments": note, "cached_at": now.isoformat(timespec="seconds")}
                dirty = True
        if note:
            text = note if note.startswith(FAILURE_PREFIXES) else AI_NOTE_PREFIX + note
            dep["comments"] = " ".join(part for part in (dep.get("comments"), text) if part)
    if dirty and writable:
        save_ai_cache(cache_path, cache)
