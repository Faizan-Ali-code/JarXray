"""
Recommended upgrade per vulnerable dependency, from published data rather than an AI guess:

  * OSV.dev (https://osv.dev) - the vulnerability database the GitHub Advisory
    Database and others feed - is asked which advisories affect
    groupId:artifactId:version, and in which version each one is fixed;
  * Maven Central's maven-metadata.xml gives the artifact's released versions.

The recommendation is the smallest stable release at or above every fix,
checked against OSV again (a fix for one advisory can still be affected by
another). The same OSV answer also triages dependency-check's findings:
dependency-check identifies products by CPE name matching, which produces
false positives; a CVE that OSV also lists for this exact package (by purl) is
"confirmed", one it does not list is worth a second look.

Results are cached in work/cache/fix_lookup.json for FIX_CACHE_HOURS (default
24) so a daily run does not repeat every request. FIX_LOOKUP=no turns the
whole step off (offline machines).
"""
import json
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from . import TOOL_VERSION
from .config import flag

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAVEN_METADATA_URL = "https://repo1.maven.org/maven2/{group}/{artifact}/maven-metadata.xml"
TIMEOUT_SECONDS = 20
MAX_CONSECUTIVE_FAILURES = 3   # then stop asking for the rest of the run (network down, proxy needed)
MAX_UPGRADE_STEPS = 5          # fixes that are themselves affected: how far to walk up before giving up

FIX_AVAILABLE = "Fix available"
NO_FIX = "No fixed release yet"
NOT_IN_OSV = "Not confirmed by OSV"
NO_COORDINATES = "Unknown (no Maven coordinates)"
LOOKUP_FAILED = "Lookup failed"
LOOKUP_OFF = "Not looked up"

# ------------------------------------------------------------------ versions

_QUALIFIER_RANK = {"alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3, "rc": -2, "cr": -2,
                   "snapshot": -1, "": 0, "ga": 0, "final": 0, "release": 0, "sp": 1}
_PRE_RELEASE = re.compile(r"(?i)(alpha|beta|milestone|preview|snapshot|incubat|\brc|\bcr|\bea\b|[.-]m\d|[.-]b\d)")


def version_key(version: str) -> tuple:
    """Sort key close to Maven's ComparableVersion: 1.0 == 1.0.0 == 1.0.Final, 1.0-rc1 < 1.0 < 1.0.1."""
    text = (version or "").lower()
    numbers, rest = [], text
    match = re.match(r"\d+(?:\.\d+)*", text)
    if match:
        numbers = [int(n) for n in match.group(0).split(".")]
        rest = text[match.end():]
    while numbers and numbers[-1] == 0:
        numbers.pop()
    words = re.findall(r"[a-z]+", rest)
    rank = min((_QUALIFIER_RANK.get(w, 0) for w in words), default=0)
    tail = [int(n) for n in re.findall(r"\d+", rest)]
    return (numbers, rank, tail)


def is_stable(version: str) -> bool:
    return not _PRE_RELEASE.search(version or "")


# ------------------------------------------------------------------ OSV ranges

def _event_steps(events):
    """OSV range events as (kind, version) in order; introduced "0" means "from the first release"."""
    for event in events:
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in event:
                yield kind, event[kind]


def first_fix(vuln: dict, package: str, version: str):
    """The version that fixes `vuln` for someone on `version`: the 'fixed' event closing the affected
    range that contains it. None when that range has no fix (or the version is not in any range)."""
    current = version_key(version)
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != "Maven" or pkg.get("name") != package:
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            inside = False
            for kind, value in _event_steps(rng.get("events") or []):
                if kind == "introduced":
                    inside = value == "0" or version_key(value) <= current
                elif inside and kind == "fixed":
                    if current < version_key(value):
                        return value
                    inside = False
                elif inside and kind == "last_affected":
                    if current <= version_key(value):
                        return None
                    inside = False
    return None


def next_fix_above(vuln: dict, package: str, version: str):
    """The smallest 'fixed' version above `version` in ANY range of `vuln`: the fix on a newer release
    line when the line `version` belongs to will not get one (e.g. Spring 5.3.x -> 6.2.x)."""
    current = version_key(version)
    fixed = [value for affected in vuln.get("affected") or []
             if (affected.get("package") or {}).get("name") == package
             for rng in affected.get("ranges") or [] if rng.get("type") == "ECOSYSTEM"
             for kind, value in _event_steps(rng.get("events") or [])
             if kind == "fixed" and version_key(value) > current]
    return min(fixed, key=version_key) if fixed else None


def flavor(version: str) -> frozenset:
    """Build variants that are not version qualifiers: '31.1-jre' -> {'jre'}, '33.0-android' -> {'android'}."""
    rest = re.sub(r"^\d+(?:\.\d+)*", "", (version or "").lower())
    return frozenset(w for w in re.findall(r"[a-z]+", rest) if w not in _QUALIFIER_RANK)


def advisory_ids(vulns: list) -> set:
    """Every identifier OSV knows these advisories by (GHSA-..., CVE-..., ...), upper-case."""
    return {i.upper() for v in vulns for i in [v.get("id", ""), *(v.get("aliases") or [])] if i}


# ------------------------------------------------------------------ HTTP + cache

class FixLookupError(Exception):
    """OSV or Maven Central could not be reached or answered something unusable."""


def _http(url: str, body: dict = None) -> bytes:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={
        "User-Agent": f"JarXray/{TOOL_VERSION}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return b""
        raise FixLookupError(f"HTTP {exc.code} from {url}") from None
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise FixLookupError(f"{url}: {getattr(exc, 'reason', exc)}") from None


class FixLookup:
    """One instance per run: talks to OSV / Maven Central through `http` (injectable for tests)."""

    def __init__(self, cache_path: Path = None, ttl_hours: float = 24, http=_http, clock=time.time):
        self.cache_path = Path(cache_path) if cache_path else None
        self.ttl = ttl_hours * 3600
        self.http = http
        self.clock = clock
        self.failures = 0
        self.cache = self._load()
        self.dirty = False

    # -- cache
    def _load(self) -> dict:
        if not self.cache_path or not self.cache_path.exists():
            return {}
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}  # a disposable cache: start over rather than fail the run

    def save(self) -> None:
        if not self.cache_path or not self.dirty:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.cache, indent=1, sort_keys=True), encoding="utf-8")
            tmp.replace(self.cache_path)
        except OSError as exc:
            print(f"  WARNING: could not save {self.cache_path.name}: {exc}")

    def _cached(self, key: str, fetch):
        entry = self.cache.get(key)
        if isinstance(entry, dict) and self.clock() - entry.get("at", 0) < self.ttl:
            return entry["value"]
        if self.failures >= MAX_CONSECUTIVE_FAILURES:
            raise FixLookupError("skipped after repeated network failures")
        try:
            value = fetch()
        except FixLookupError:
            self.failures += 1
            raise
        self.failures = 0
        self.cache[key] = {"at": self.clock(), "value": value}
        self.dirty = True
        return value

    # -- sources
    def osv_vulns(self, package: str, version: str) -> list:
        def fetch():
            raw = self.http(OSV_QUERY_URL, {"package": {"ecosystem": "Maven", "name": package}, "version": version})
            try:
                vulns = json.loads(raw or b"{}").get("vulns") or []
            except ValueError:
                raise FixLookupError("OSV answered with invalid JSON") from None
            # keep only what the recommendation needs
            return [{"id": v.get("id", ""), "aliases": v.get("aliases") or [],
                     "affected": [a for a in v.get("affected") or []
                                  if (a.get("package") or {}).get("name") == package]} for v in vulns]
        return self._cached(f"osv|{package}|{version}", fetch)

    def maven_versions(self, group: str, artifact: str) -> list:
        def fetch():
            raw = self.http(MAVEN_METADATA_URL.format(group=group.replace(".", "/"), artifact=artifact))
            if not raw:
                return []  # not on Maven Central (internal repository, relocated artifact)
            try:
                root = ET.fromstring(raw)
            except ET.ParseError:
                raise FixLookupError("Maven Central answered with invalid XML") from None
            return [v.text.strip() for v in root.iter("version") if v.text]
        return self._cached(f"maven|{group}:{artifact}", fetch)

    # -- the recommendation
    def recommend(self, group: str, artifact: str, version: str) -> dict:
        """{status, recommended_version, comments, confirmed_ids (set of CVE/GHSA ids) or None}."""
        if not group or not version or version == "UNKNOWN":
            return _result(NO_COORDINATES, comments="dependency-check found no Maven coordinates for this jar; "
                                                    "check its version by hand.")
        package = f"{group}:{artifact}"
        try:
            vulns = self.osv_vulns(package, version)
            if not vulns:
                return _result(NOT_IN_OSV, confirmed=set(), comments=(
                    f"OSV lists no advisory for {package} {version}: dependency-check matched it by CPE name "
                    "only - check for a false positive before acting."))
            stable = sorted((v for v in self.maven_versions(group, artifact) if is_stable(v)), key=version_key)
            return self._walk_up(package, version, vulns, stable)
        except FixLookupError as exc:
            return _result(LOOKUP_FAILED, comments=f"Could not reach OSV / Maven Central ({exc}).")

    def _walk_up(self, package: str, version: str, vulns: list, stable: list) -> dict:
        confirmed = advisory_ids(vulns)
        # Stay on the build variant in use (guava 31.1-jre -> a -jre release, not -android).
        same_flavor = [s for s in stable if flavor(s) == flavor(version)]
        stable = same_flavor or stable
        latest = stable[-1] if stable else None
        current, remaining, new_line = version, vulns, False
        for _ in range(MAX_UPGRADE_STEPS):
            fixes = []
            for vuln in remaining:
                fix = first_fix(vuln, package, current)
                if fix is None:  # this release line gets no fix; a newer line may have one
                    fix = next_fix_above(vuln, package, current)
                    new_line = new_line or fix is not None
                fixes.append(fix)
            if None in fixes:
                unfixed = ", ".join(v["id"] for v, f in zip(remaining, fixes) if f is None)
                return _result(NO_FIX, confirmed=confirmed, comments=(
                    f"No fixed release published for {unfixed}" + (f" (latest stable: {latest})." if latest else ".")))
            target = max(fixes, key=version_key)
            candidate = next((s for s in stable if version_key(s) >= version_key(target)), target)
            remaining = self.osv_vulns(package, candidate)
            if not remaining:
                note = f"First release with no OSV advisory for this package: {candidate}"
                if latest and latest != candidate:
                    note += f" (latest stable: {latest})"
                if new_line:
                    note += (f". The {version} release line has no fix: this is a move to a newer line - "
                             f"expect breaking changes")
                return _result(FIX_AVAILABLE, candidate, confirmed, note + ".")
            current = candidate
        return _result(NO_FIX, confirmed=confirmed, comments=(
            f"Every release up to {current} still has OSV advisories; check the project's own guidance."))


def _result(status, recommended="NA", confirmed=None, comments=""):
    return {"status": status, "recommended_version": recommended, "confirmed_ids": confirmed, "comments": comments}


def apply_fix_lookup(config: dict, cache_dir: Path, dependencies: list, lookup: FixLookup = None) -> dict:
    """Adds status / recommended_version / comments to each dependency and marks every CVE as confirmed
    (True), not listed by OSV (False) or unknown (None). Returns counts for the report summary."""
    stats = {"looked_up": False, "confirmed": 0, "unconfirmed": 0, "unknown": 0}
    if not flag(config, "FIX_LOOKUP", "yes"):
        for dep in dependencies:
            dep.update(status=LOOKUP_OFF, recommended_version="NA",
                       comments="FIX_LOOKUP=no in config.txt: look up the fixed version by hand.")
            for v in dep["vulnerabilities"]:
                v["osv_confirmed"] = None
        stats["unknown"] = sum(len(d["vulnerabilities"]) for d in dependencies)
        return stats

    if lookup is None:
        try:
            ttl = float(config.get("FIX_CACHE_HOURS") or 24)
        except ValueError:
            ttl = 24
        lookup = FixLookup(Path(cache_dir) / "fix_lookup.json", ttl)
    stats["looked_up"] = True
    for dep in dependencies:
        print(f"    Checking OSV / Maven Central for {dep['group_id'] or '?'}:{dep['artifact_id']}:{dep['version']} ...")
        result = lookup.recommend(dep["group_id"], dep["artifact_id"], dep["version"])
        confirmed = result.pop("confirmed_ids")
        dep.update(result)
        for v in dep["vulnerabilities"]:
            v["osv_confirmed"] = None if confirmed is None else v["cve_id"].upper() in confirmed
            key = {True: "confirmed", False: "unconfirmed", None: "unknown"}[v["osv_confirmed"]]
            stats[key] += 1
    lookup.save()
    return stats
