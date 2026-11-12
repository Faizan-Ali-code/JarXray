"""Recommended versions come from OSV + Maven Central, and each CVE is confirmed or questioned by OSV."""
import pytest

from conftest import FakeHttp, osv_vuln
from jarxray import fix_lookup as fl

LOG4J = "org.apache.logging.log4j:log4j-core"
GROUP, ARTIFACT = LOG4J.split(":")


def log4shell(fixed, cve, introduced="2.0-beta9"):
    return osv_vuln(f"GHSA-{cve[-5:]}", LOG4J, [{"introduced": introduced}, {"fixed": fixed}], aliases=[cve])


ALL_FOUR = [log4shell("2.15.0", "CVE-2021-44228"), log4shell("2.16.0", "CVE-2021-45046"),
            log4shell("2.17.0", "CVE-2021-45105"), log4shell("2.17.1", "CVE-2021-44832")]
VERSIONS = ["2.14.1", "2.15.0", "2.16.0", "2.17.0", "2.17.1", "2.18.0", "2.19.0-rc1", "3.0.0-beta1"]


def lookup(**kwargs):
    return fl.FixLookup(cache_path=None, http=FakeHttp(**kwargs))


# ------------------------------------------------------------------ versions

@pytest.mark.parametrize("smaller,bigger", [
    ("1.0", "1.0.1"), ("1.0-rc1", "1.0"), ("2.9", "2.10"), ("4.2.16.Final", "4.2.17.Final"),
    ("1.0-alpha", "1.0-beta"), ("5.3.18.RELEASE", "5.3.19"), ("2.0-beta9", "2.0"),
])
def test_version_order(smaller, bigger):
    assert fl.version_key(smaller) < fl.version_key(bigger)


def test_equivalent_versions():
    assert fl.version_key("1.0") == fl.version_key("1.0.0") == fl.version_key("1.0.Final")


@pytest.mark.parametrize("version,stable", [
    ("2.17.1", True), ("31.1-jre", True), ("4.1.100.Final", True), ("2.19.0-rc1", False), ("3.0.0-beta1", False),
    ("1.0-SNAPSHOT", False), ("6.0.0-M2", False), ("1.0.0-alpha", False),
])
def test_stable_releases(version, stable):
    assert fl.is_stable(version) is stable


# ------------------------------------------------------------------ OSV ranges

def test_first_fix_picks_the_range_containing_the_version():
    vuln = osv_vuln("X", LOG4J, [{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"},
                                 {"introduced": "2.4"}, {"fixed": "2.12.2"}, {"introduced": "2.13.0"}, {"fixed": "2.15.0"}])
    assert fl.first_fix(vuln, LOG4J, "2.1") == "2.3.1"
    assert fl.first_fix(vuln, LOG4J, "2.11.0") == "2.12.2"
    assert fl.first_fix(vuln, LOG4J, "2.14.1") == "2.15.0"
    assert fl.first_fix(vuln, "other:pkg", "2.14.1") is None


def test_first_fix_without_a_fixed_event():
    assert fl.first_fix(osv_vuln("X", LOG4J, [{"introduced": "0"}]), LOG4J, "1.0") is None
    assert fl.first_fix(osv_vuln("X", LOG4J, [{"introduced": "0"}, {"last_affected": "2.0"}]), LOG4J, "1.0") is None


# ------------------------------------------------------------------ recommendation

def test_recommends_first_release_without_advisories():
    result = lookup(osv={(LOG4J, "2.14.1"): ALL_FOUR}, maven={(GROUP, ARTIFACT): VERSIONS}).recommend(
        GROUP, ARTIFACT, "2.14.1")
    assert result["status"] == fl.FIX_AVAILABLE and result["recommended_version"] == "2.17.1"
    assert "latest stable: 2.18.0" in result["comments"]          # pre-releases are not "latest stable"
    assert {"CVE-2021-44228", "CVE-2021-44832"} <= result["confirmed_ids"]


def test_walks_up_when_a_fix_is_itself_affected():
    osv = {(LOG4J, "2.14.1"): [log4shell("2.15.0", "CVE-2021-44228")],
           (LOG4J, "2.15.0"): [log4shell("2.16.0", "CVE-2021-45046", introduced="2.15.0")]}
    result = lookup(osv=osv, maven={(GROUP, ARTIFACT): VERSIONS}).recommend(GROUP, ARTIFACT, "2.14.1")
    assert result["recommended_version"] == "2.16.0"


def test_stays_on_the_build_flavor():
    guava = "com.google.guava:guava"
    osv = {(guava, "31.1-jre"): [osv_vuln("GHSA-g", guava, [{"introduced": "0"}, {"fixed": "32.0.0-android"}],
                                          aliases=["CVE-2023-2976"])]}
    versions = ["31.1-jre", "31.1-android", "32.0.0-android", "32.0.0-jre", "33.0.0-android", "33.0.0-jre"]
    result = lookup(osv=osv, maven={("com.google.guava", "guava"): versions}).recommend(
        "com.google.guava", "guava", "31.1-jre")
    assert result["recommended_version"] == "32.0.0-jre" and "latest stable: 33.0.0-jre" in result["comments"]


def test_fix_only_on_a_newer_release_line():
    spring = "org.springframework:spring-core"
    events = [{"introduced": "5.3.0"}, {"last_affected": "5.3.45"}, {"introduced": "6.2.0"}, {"fixed": "6.2.11"}]
    osv = {(spring, "5.3.18"): [osv_vuln("GHSA-s", spring, events, aliases=["CVE-2025-41249"])]}
    result = lookup(osv=osv, maven={("org.springframework", "spring-core"): ["5.3.18", "6.2.10", "6.2.11", "7.0.1"]}
                    ).recommend("org.springframework", "spring-core", "5.3.18")
    assert result["status"] == fl.FIX_AVAILABLE and result["recommended_version"] == "6.2.11"
    assert "newer line" in result["comments"]


def test_no_fixed_release():
    osv = {(LOG4J, "2.14.1"): [osv_vuln("GHSA-open", LOG4J, [{"introduced": "0"}], aliases=["CVE-2099-1"])]}
    result = lookup(osv=osv, maven={(GROUP, ARTIFACT): VERSIONS}).recommend(GROUP, ARTIFACT, "2.14.1")
    assert result["status"] == fl.NO_FIX and result["recommended_version"] == "NA"
    assert "GHSA-open" in result["comments"]


def test_finding_not_in_osv_is_flagged_as_possible_false_positive():
    result = lookup().recommend("org.x", "y", "1.0")
    assert result["status"] == fl.NOT_IN_OSV and result["confirmed_ids"] == set()
    assert "false positive" in result["comments"]


def test_missing_coordinates_and_network_failures():
    assert lookup().recommend("", "y", "1.0")["status"] == fl.NO_COORDINATES
    broken = lookup(fail=True)
    for _ in range(fl.MAX_CONSECUTIVE_FAILURES + 2):
        assert broken.recommend("org.x", "y", "1.0")["status"] == fl.LOOKUP_FAILED
    assert len(broken.http.calls) == fl.MAX_CONSECUTIVE_FAILURES   # then it stops trying


def test_cache_is_reused_until_it_expires(tmp_path):
    now = [1000.0]
    http = FakeHttp(osv={(LOG4J, "2.14.1"): ALL_FOUR}, maven={(GROUP, ARTIFACT): VERSIONS})
    first = fl.FixLookup(tmp_path / "cache.json", ttl_hours=24, http=http, clock=lambda: now[0])
    first.recommend(GROUP, ARTIFACT, "2.14.1")
    first.save()
    calls = len(http.calls)
    again = fl.FixLookup(tmp_path / "cache.json", ttl_hours=24, http=http, clock=lambda: now[0])
    assert again.recommend(GROUP, ARTIFACT, "2.14.1")["recommended_version"] == "2.17.1"
    assert len(http.calls) == calls                                   # all answers came from the cache
    now[0] += 25 * 3600
    again.recommend(GROUP, ARTIFACT, "2.14.1")
    assert len(http.calls) > calls                                    # stale: asked again


def test_corrupt_cache_is_ignored(tmp_path):
    (tmp_path / "cache.json").write_text("{not json", encoding="utf-8")
    assert fl.FixLookup(tmp_path / "cache.json").cache == {}


# ------------------------------------------------------------------ applying it to a report

def _dep(cves):
    return {"group_id": GROUP, "artifact_id": ARTIFACT, "version": "2.14.1", "file_name": "log4j-core-2.14.1.jar",
            "vulnerabilities": [{"cve_id": c} for c in cves]}


def test_apply_marks_each_cve_and_counts():
    dep = _dep(["CVE-2021-44228", "CVE-2020-9999"])
    stats = fl.apply_fix_lookup({}, None, [dep], lookup(osv={(LOG4J, "2.14.1"): ALL_FOUR},
                                                         maven={(GROUP, ARTIFACT): VERSIONS}))
    assert [v["osv_confirmed"] for v in dep["vulnerabilities"]] == [True, False]
    assert stats == {"looked_up": True, "confirmed": 1, "unconfirmed": 1, "unknown": 0}
    assert dep["recommended_version"] == "2.17.1" and dep["status"] == fl.FIX_AVAILABLE


def test_lookup_can_be_switched_off():
    dep = _dep(["CVE-2021-44228"])
    stats = fl.apply_fix_lookup({"FIX_LOOKUP": "no"}, None, [dep])
    assert dep["status"] == fl.LOOKUP_OFF and dep["vulnerabilities"][0]["osv_confirmed"] is None
    assert stats["looked_up"] is False and stats["unknown"] == 1
