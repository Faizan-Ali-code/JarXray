"""The dependency risk report and the analysis sheet, and the optional AI notes."""
import json
import zipfile
from datetime import datetime, timedelta

from jarxray import ai_lookup
from jarxray.fix_lookup import FIX_AVAILABLE, NOT_IN_OSV
from jarxray.report_html import build_risk_html_report
from jarxray.report_ods import build_ods_report


def _deps():
    return [
        {"file_name": "log4j-core-2.14.1.jar", "related_files": [], "group_id": "org.apache.logging.log4j",
         "artifact_id": "log4j-core", "version": "2.14.1", "highest_severity": "CRITICAL",
         "identification_confidence": "HIGHEST", "recommended_version": "2.17.1", "status": FIX_AVAILABLE,
         "comments": "First release with no OSV advisory",
         "vulnerabilities": [{"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "cvss_score": 10.0,
                              "cvss_version": "v3", "description": "JNDI", "osv_confirmed": True}]},
        {"file_name": "<img src=x onerror=alert(1)>.jar", "related_files": [], "group_id": "", "artifact_id": "x",
         "version": "1", "highest_severity": "HIGH", "identification_confidence": "LOW", "recommended_version": "NA",
         "status": NOT_IN_OSV, "comments": "",
         "vulnerabilities": [{"cve_id": "CVE-2020-1", "severity": "HIGH", "cvss_score": None, "cvss_version": None,
                              "description": "<script>alert(1)</script>", "osv_confirmed": False}]},
    ]


def test_risk_report(tmp_path):
    path = tmp_path / "r.html"
    triage = {"looked_up": True, "confirmed": 1, "unconfirmed": 1, "unknown": 0}
    build_risk_html_report(_deps(), path, "Orders", "ORD", "QA", total_scanned=10, triage=triage)
    html = path.read_text(encoding="utf-8")
    assert "Dependency Risk Report" in html and "pentest" not in html.lower()
    assert "not a penetration test" in html
    assert "OSV &#10003;" in html and "not in OSV" in html
    assert "<strong>1</strong> of 2 CVE findings confirmed by OSV" in html
    assert "CPE match confidence: LOW" in html
    assert "<script>alert" not in html and "<img src=x" not in html          # everything escaped


def test_analysis_sheet(tmp_path):
    path = tmp_path / "a.ods"
    build_ods_report(_deps(), path, "Orders", "ORD", "QA")
    with zipfile.ZipFile(path) as zf:
        content = zf.read("content.xml").decode("utf-8")
    assert "CPE Confidence" in content and "OSV: not listed - possible false positive" in content


class FakeClient:
    def __init__(self, text):
        self.text, self.prompts = text, []

    @property
    def responses(self):
        return self

    def create(self, **kwargs):
        self.prompts.append(kwargs["input"])
        return type("R", (), {"output_text": self.text})()


CONFIG = {"ENABLE_AI": "yes", "OPENAI_API_KEY": "k", "AI_USE_WEB_SEARCH": "no"}


def test_ai_note_is_labelled_and_cached(tmp_path):
    deps = _deps()[:1]
    client = FakeClient('{"comments": "Needs Java 8+."}')
    ai_lookup.add_ai_notes(CONFIG, tmp_path, deps, client=client)
    assert deps[0]["comments"].endswith("AI note (unverified): Needs Java 8+.")
    assert deps[0]["recommended_version"] == "2.17.1"          # the AI cannot change the recommendation
    assert "2.17.1" in client.prompts[0]
    cache = json.loads((tmp_path / "ai_recommendation_cache.json").read_text(encoding="utf-8"))
    assert list(cache.values())[0]["comments"] == "Needs Java 8+."

    again = FakeClient('{"comments": "should not be asked"}')
    ai_lookup.add_ai_notes(CONFIG, tmp_path, _deps()[:1], client=again)
    assert again.prompts == []
    later = datetime.now() + timedelta(days=31)
    ai_lookup.add_ai_notes(CONFIG, tmp_path, _deps()[:1], client=again, now=later)
    assert len(again.prompts) == 1                               # older than AI_CACHE_DAYS: refreshed


def test_ai_failures_are_shown_but_not_cached(tmp_path):
    deps = _deps()[:1]
    ai_lookup.add_ai_notes(CONFIG, tmp_path, deps, client=FakeClient("no json here"))
    assert "AI response could not be parsed" in deps[0]["comments"]
    assert not (tmp_path / "ai_recommendation_cache.json").exists()


def test_ai_off_changes_nothing(tmp_path):
    deps = _deps()[:1]
    ai_lookup.add_ai_notes({"ENABLE_AI": "no"}, tmp_path, deps, client=FakeClient('{"comments": "x"}'))
    assert deps[0]["comments"] == "First release with no OSV advisory"
