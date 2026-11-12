"""Parses dependency-check's JSON output into structured per-dependency CVE records."""
import json
import re
from pathlib import Path

from .jar_classifier import base_file_name, filename_looks_internal, group_id_is_internal
from .severity import severity_rank

# A purl may carry qualifiers and a subpath after the version
# (pkg:maven/g/a@1.0?type=jar#sub), which must NOT end up inside the version -
# they would corrupt both the reported version and the AI cache key.
PURL_MAVEN_RE = re.compile(r'^pkg:maven/(?P<group>[^/]+)/(?P<artifact>[^@]+)@(?P<version>[^?#]+)')

# Fallback pattern for "artifactId-version.jar" style names, used when a jar
# has no purl/pom.properties metadata to read groupId/artifactId/version from.
FILENAME_VERSION_RE = re.compile(
    r"^(?P<artifact>.+?)-(?P<version>\d+(?:\.\d+){0,3}(?:[-.](?:RELEASE|SNAPSHOT|GA|FINAL|[A-Za-z0-9]+))?)"
    r"(?:-(?P<classifier>sources|javadoc))?\.jar$",
    re.IGNORECASE,
)

# (version label, JSON key, key holding that version's severity, key holding its score).
# dependency-check writes the v2 score as "score" but v3/v4 as "baseScore".
_CVSS_BLOCKS = (
    ("v4", "cvssv4", "baseSeverity", ("baseScore",)),
    ("v3", "cvssv3", "baseSeverity", ("baseScore",)),
    ("v2", "cvssv2", "severity", ("score", "baseScore")),
)


def _load(json_path: Path) -> dict:
    with open(json_path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "dependencies" not in data:
        # e.g. the GitLab/Jenkins-format JSON dependency-check writes for
        # OUTPUT_FORMAT=ALL - reading it as "no dependencies" would turn a
        # vulnerable application into a clean report.
        raise ValueError(f"{Path(json_path).name} is not a dependency-check JSON report (no 'dependencies').")
    return data


def _cvss_score(vuln: dict, severity: str) -> tuple:
    """(score, 'v4'|'v3'|'v2') for the CVSS version dependency-check took the
    severity label from, so a row never pairs e.g. a v4 'LOW' with a v3 7.5."""
    present = []
    for version, key, severity_key, score_keys in _CVSS_BLOCKS:
        block = vuln.get(key) or {}
        score = next((block[k] for k in score_keys if block.get(k) is not None), None)
        if score is not None:
            present.append((score, version, str(block.get(severity_key) or "").upper()))
    for score, version, block_severity in present:
        if block_severity == severity:
            return score, version
    if present:
        return present[0][0], present[0][1]
    return None, None


_CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "HIGHEST": 4}


def _identification_confidence(dep: dict) -> str:
    """Highest confidence of the CPE identifiers dependency-check used to look up vulnerabilities
    ("" if it reports none). LOW/MEDIUM CPE matches are the usual source of false positives."""
    levels = [str(i.get("confidence") or "").upper() for i in dep.get("vulnerabilityIds") or []]
    levels = [lvl for lvl in levels if lvl in _CONFIDENCE_RANK]
    return max(levels, key=_CONFIDENCE_RANK.get) if levels else ""


def looks_internal(group_id, file_name: str, internal_prefixes) -> bool:
    """The Maven groupId decides when dependency-check found one; the file name only when it did not.

    A file name alone is weak evidence: "example-app.jar: log4j-core-2.14.1.jar" (a library inside an
    internal archive) or a shaded entry of an internal jar must still be reported."""
    if group_id:
        return group_id_is_internal(group_id, internal_prefixes)
    return filename_looks_internal(Path(base_file_name(file_name)), internal_prefixes)


def _related_files(dep: dict, parent_name: str, internal_prefixes) -> list:
    """Jars dependency-check identified as the same library and folded into
    this entry (e.g. every netty-*-4.2.17 jar under netty-transport). They
    share its CVEs and must be upgraded together, so the report lists them."""
    related = []
    for rel in dep.get("relatedDependencies") or []:
        name = rel.get("fileName")
        if not name:
            continue
        group = next((m.group("group") for m in (PURL_MAVEN_RE.match(p.get("id", ""))
                                                   for p in rel.get("packageIds") or []) if m), None)
        if looks_internal(group, name, internal_prefixes):
            print(f"  WARNING: related jar '{name}' (under {parent_name}) looks like an internal "
                  f"dependency but was still present in the scan - left out of the report.")
            continue
        related.append(name)
    return sorted(set(related))


def parse_dependency_check_json(json_path: Path, internal_prefixes=()) -> list:
    """
    Reads dependency-check's JSON output and returns one entry per VULNERABLE
    dependency only (clean dependencies are not included - matches the scope
    of the analysis sheet, which is an action list, not a full inventory).
    Dependencies matching internal_prefixes (INTERNAL_PACKAGES) are left out.

    Each entry: {file_name, related_files, group_id, artifact_id, version, highest_severity,
                 vulnerabilities: [{cve_id, severity, cvss_score, cvss_version, description}]}
    """
    data = _load(json_path)

    results = []
    for dep in data.get("dependencies") or []:
        vulns = dep.get("vulnerabilities") or []
        if not vulns:
            continue

        file_name = dep.get("fileName", "unknown.jar")
        group_id, artifact_id, version = None, None, None

        for pkg in dep.get("packages", []) or []:
            m = PURL_MAVEN_RE.match(pkg.get("id", ""))
            if m:
                group_id = m.group("group")
                artifact_id = m.group("artifact")
                version = m.group("version")
                break

        if not artifact_id:
            m = FILENAME_VERSION_RE.match(base_file_name(file_name))
            if m:
                artifact_id = m.group("artifact")
                version = m.group("version")
            else:
                artifact_id = Path(file_name).stem
                version = "UNKNOWN"

        vuln_list = []
        highest_rank = -1
        highest_severity = "UNKNOWN"
        for v in vulns:
            sev = (v.get("severity") or "UNKNOWN").upper()
            rank = severity_rank(sev)
            if rank > highest_rank:
                highest_rank = rank
                highest_severity = sev

            score, cvss_version = _cvss_score(v, sev)
            vuln_list.append({
                "cve_id": v.get("name", "UNKNOWN"),
                "severity": sev,
                "cvss_score": score,
                "cvss_version": cvss_version,
                "description": (v.get("description") or "").strip(),
            })

        # Sort so the most severe CVEs are listed first in the CVE Details column
        vuln_list.sort(key=lambda v: severity_rank(v["severity"]), reverse=True)

        # Internal code is never reported. Most internal jars were set aside before the scan; those
        # still here are either shaded archives kept on purpose (their third-party content is reported
        # under its own coordinates) or jars the separation missed - filtered here either way.
        if looks_internal(group_id, file_name, internal_prefixes):
            print(f"  NOTE: '{file_name}' (groupId={group_id or 'unknown'}) is internal code - "
                  f"left out of the report.")
            continue

        results.append({
            "file_name": file_name,
            "related_files": _related_files(dep, file_name, internal_prefixes),
            "group_id": group_id or "",
            "artifact_id": artifact_id,
            "version": version or "UNKNOWN",
            "highest_severity": highest_severity,
            "vulnerabilities": vuln_list,
            # dependency-check's own confidence that it identified the right product (CPE match).
            "identification_confidence": _identification_confidence(dep),
        })

    # Most severe dependencies first
    results.sort(key=lambda d: severity_rank(d["highest_severity"]), reverse=True)
    return results


def count_total_dependencies(json_path: Path) -> int:
    """Files dependency-check scanned (vulnerable + clean, related jars
    included - the first number of its own 'Dependencies Scanned: 242 (179
    unique)'), for the executive summary."""
    try:
        data = _load(json_path)
    except (OSError, ValueError):
        return 0
    deps = data.get("dependencies") or []
    return len(deps) + sum(len(d.get("relatedDependencies") or []) for d in deps)


def read_analysis_exceptions(json_path: Path) -> list:
    """The non-fatal analyzer errors dependency-check recorded while still
    completing the scan (it exits non-zero when there are any)."""
    try:
        data = _load(json_path)
    except (OSError, ValueError):
        return []
    messages = []
    for entry in (data.get("scanInfo") or {}).get("analysisExceptions") or []:
        exc = entry.get("exception") if isinstance(entry, dict) else None
        message = (exc or {}).get("message") if isinstance(exc, dict) else None
        messages.append(str(message or entry))
    return messages
