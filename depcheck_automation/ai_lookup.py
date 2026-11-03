"""AI-assisted 'latest secure version' lookup, with a permanent on-disk cache."""
import json
import os
import re
from datetime import datetime
from pathlib import Path

from .config import flag

DEFAULT_STATUS = "Latest and vulnerable"

# Comments the tool itself writes when there is no real AI answer. Entries
# like these are never cached, and ones already in an older cache are retried.
FAILURE_PREFIXES = ("AI lookup failed", "AI lookup skipped", "AI response could not be parsed")
PLACEHOLDER_COMMENT_PREFIXES = FAILURE_PREFIXES + ("AI lookup disabled",)

UNKNOWN_GROUP_TEXT = "(groupId unknown - identify it from the jar file name)"

_BUILT_IN_TEMPLATE = (
    "You are a Java dependency security analyst. Research the Maven artifact below "
    "and determine its true latest stable release, then decide whether that release "
    "is secure or still vulnerable.\n\n"
    "Artifact: {{GROUP_ID}}:{{ARTIFACT_ID}}\n"
    "Jar file: {{FILE_NAME}}\n"
    "Current version: {{VERSION}}\n"
    "Known vulnerabilities:\n{{CVE_SUMMARY}}\n\n"
    "Rules:\n"
    "- If the groupId is not known, work out the artifact's real Maven groupId from the jar "
    "file name first; never treat the word 'unknown' as a groupId.\n"
    "- Do NOT limit your search to the same minor/major series as the current version. "
    "Find the actual latest stable release across ALL series, even if that means jumping "
    "series entirely (e.g. current is 5.5.2, latest in 5.5.x is still 5.5.2, but 5.6.4 is "
    "newer overall - the correct answer is 5.6.4).\n"
    "- Exclude alpha/beta/RC/milestone builds - \"latest stable\" means production-ready.\n"
    "- recommended_version must be that latest stable release of the SAME artifact (same "
    "groupId:artifactId) IF it resolves the listed CVEs. If the latest stable release "
    "anywhere still has these CVEs unresolved, set it to \"NA\".\n"
    "- If the artifact has been renamed, relocated, or superseded by a different artifact, "
    "keep recommended_version as \"NA\" and explain the migration path in comments instead.\n"
    "- status must reflect the latest stable release found, not the version currently in "
    "use: \"Latest and secure available\" if any fix exists, or \"Latest and vulnerable\" "
    "only if no fix exists anywhere yet.\n"
    "- comments should be brief (one sentence), and empty string if there is nothing extra to add.\n\n"
    "Respond with ONLY a JSON object, no other text, in this exact shape:\n"
    '{"recommended_version": "...", "status": "...", "comments": "..."}'
)


# --------------------------------------------------------------------------- #
# The permanent cache (config/ai_recommendation_cache.json)
# --------------------------------------------------------------------------- #
def _read_cache(cache_path: Path) -> tuple:
    """(cache, safe_to_save). Every entry in the cache is a paid-for answer,
    so an unreadable file is kept aside rather than overwritten."""
    if not cache_path.exists():
        return {}, True
    try:
        text = cache_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        # Locked or otherwise temporarily unreadable: don't clobber it on save.
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
            kept = f"the unreadable file was kept as {backup.name} so it can be repaired"
        except OSError:
            print(f"  WARNING: could not read {cache_path.name} ({exc}) and could not set it aside - "
                  f"AI answers from this run won't be cached.")
            return {}, False
        print(f"  WARNING: could not read {cache_path.name} ({exc}) - starting with an empty cache; {kept}.")
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


def _ai_cache_key(group_id: str, artifact_id: str, version: str) -> str:
    return f"{group_id or 'unknown'}:{artifact_id}:{version}"


def _is_failure(result: dict) -> bool:
    return bool(result.get("_failed")) or str(result.get("comments") or "").startswith(FAILURE_PREFIXES)


# --------------------------------------------------------------------------- #
# The OpenAI call
# --------------------------------------------------------------------------- #
def _extract_json_object(text: str) -> dict:
    """Pulls the first {...} JSON object out of a model response, tolerating
    markdown code fences or extra prose around it."""
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


def _failure(comment: str) -> dict:
    return {"recommended_version": "NA", "status": DEFAULT_STATUS, "comments": comment, "_failed": True}


def call_openai_for_recommendation(config: dict, script_dir: Path, group_id: str,
                                     artifact_id: str, version: str, vulnerabilities: list,
                                     file_name: str = "", template: str = None) -> dict:
    try:
        from openai import OpenAI
    except ImportError:
        return _failure("AI lookup skipped: 'openai' package not installed (see scripts\\setup_venv.bat)")

    if template is None:
        template = load_prompt_template(script_dir, config)
    prompt = (
        template
        .replace("{{GROUP_ID}}", group_id or UNKNOWN_GROUP_TEXT)
        .replace("{{ARTIFACT_ID}}", artifact_id)
        .replace("{{FILE_NAME}}", file_name or f"{artifact_id}-{version}.jar")
        .replace("{{VERSION}}", version)
        .replace("{{CVE_SUMMARY}}", build_cve_summary(vulnerabilities))
    )

    client = OpenAI(api_key=config["OPENAI_API_KEY"])
    model = config.get("OPENAI_MODEL", "gpt-4o").strip()

    try:
        kwargs = {"model": model, "input": prompt}
        if flag(config, "AI_USE_WEB_SEARCH", "yes"):
            kwargs["tools"] = [{"type": "web_search_preview"}]
        response = client.responses.create(**kwargs)
        text = response.output_text
    except Exception as e:
        # NOTE: OpenAI's web-search API surface has changed shape a few times.
        # If this ever raises an error naming the "tools"/"web_search_preview"
        # parameter, check OpenAI's current docs and adjust the call above -
        # everything else in this function will keep working unchanged.
        return _failure(f"AI lookup failed: {e}")

    parsed = _extract_json_object(text)
    if not parsed:
        return _failure("AI response could not be parsed as JSON")

    # `or` before str(): a JSON null must fall back, not become the text 'None'.
    return {
        "recommended_version": str(parsed.get("recommended_version") or "NA"),
        "status": str(parsed.get("status") or DEFAULT_STATUS),
        "comments": str(parsed.get("comments") or ""),
    }


def _clean_version(value) -> str:
    text = str(value or "").strip()
    return "NA" if text.lower() in ("", "none", "null") else text


def _numeric_version(version: str):
    """'4.2.17.Final' -> (4, 2, 17); trailing zeros dropped so 1.3 == 1.3.0."""
    match = re.match(r"\d+(?:\.\d+)*", version or "")
    if not match:
        return None
    parts = [int(p) for p in match.group(0).split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def recommendation_check(current: str, recommended: str) -> str:
    """A note when the AI 'recommends' the version already in use or an older
    one - seen on real runs (e.g. spring-security-core 7.1.1 -> '7.1.0').
    Pre-release vs release of the same number (1.0.0-beta2 -> 1.0.0) is not flagged."""
    if recommended == "NA":
        return ""
    cur, rec = _numeric_version(current), _numeric_version(recommended)
    if cur is None or rec is None:
        return ""
    if rec < cur:
        return (f"Check: the AI suggested {recommended}, which is OLDER than the {current} in use - "
                f"verify before acting.")
    if recommended.strip().lower() == current.strip().lower():
        return (f"Check: the AI suggested {recommended}, the version already in use - "
                f"verify whether a fixed version exists.")
    return ""


def enrich_with_ai_recommendations(config: dict, script_dir: Path, dependencies: list) -> None:
    """Mutates each dependency dict in place, adding recommended_version/status/comments."""
    enable_ai = flag(config, "ENABLE_AI")
    cache_path = Path(script_dir) / (config.get("AI_CACHE_FILE", "").strip() or "ai_recommendation_cache.json")
    cache, cache_writable = _read_cache(cache_path) if enable_ai else ({}, False)
    cache_dirty = False
    template = load_prompt_template(script_dir, config) if enable_ai and dependencies else None

    for dep in dependencies:
        key = _ai_cache_key(dep["group_id"], dep["artifact_id"], dep["version"])

        if not enable_ai:
            dep["recommended_version"] = "NA"
            dep["status"] = DEFAULT_STATUS
            dep["comments"] = "AI lookup disabled (ENABLE_AI=no in config.txt)"
            continue

        cached = cache.get(key)
        if isinstance(cached, dict) and not _is_failure(cached):
            result = cached
        else:
            print(f"    Asking AI about {key} ...")
            result = call_openai_for_recommendation(
                config, script_dir, dep["group_id"], dep["artifact_id"], dep["version"],
                dep["vulnerabilities"], file_name=dep.get("file_name", ""), template=template,
            )
            if _is_failure(result):
                # Shown in this run's report, but asked again next run - a bad
                # key or a network outage must not become a permanent answer.
                cache.pop(key, None)
            else:
                cache[key] = {k: v for k, v in result.items() if not k.startswith("_")}
                cache_dirty = True

        # Coerced rather than taken as-is: ai_recommendation_cache.json is
        # explicitly documented as user-editable, so a hand-edited entry can
        # legitimately come back with a null (or numeric) value here.
        dep["recommended_version"] = _clean_version(result.get("recommended_version"))
        dep["status"] = str(result.get("status") or DEFAULT_STATUS)
        dep["comments"] = str(result.get("comments") or "")
        # Checked at report time, not cache time, so answers cached earlier are checked too.
        note = recommendation_check(dep["version"], dep["recommended_version"])
        if note:
            dep["comments"] = f"{note} {dep['comments']}".strip()

    if cache_dirty and cache_writable:
        save_ai_cache(cache_path, cache)
