"""Reading dependency-check's JSON report: internal code filtered by coordinates, not by file name alone."""
import json

from jarxray.dc_json import count_total_dependencies, parse_dependency_check_json


def _vuln(name, severity="HIGH", score=7.5):
    return {"name": name, "severity": severity, "cvssv3": {"baseScore": score, "baseSeverity": severity},
            "description": "<b>desc</b>"}


def _dep(file_name, purl=None, vulns=(), confidence=None, related=()):
    dep = {"fileName": file_name, "vulnerabilities": list(vulns), "relatedDependencies": list(related)}
    if purl:
        dep["packages"] = [{"id": purl}]
    if confidence:
        dep["vulnerabilityIds"] = [{"id": "cpe:2.3:a:x:y", "confidence": c} for c in confidence]
    return dep


def _report(tmp_path, deps):
    path = tmp_path / "dependency-check-report.json"
    path.write_text(json.dumps({"dependencies": deps}), encoding="utf-8")
    return path


def test_internal_code_is_filtered_by_group_id_not_file_name(tmp_path):
    path = _report(tmp_path, [
        _dep("orders-service.jar", "pkg:maven/com.example/orders-service@1.0", [_vuln("CVE-1")]),
        # a library found inside an internal archive: the outer file name looks internal, the library is not
        _dep("example-app.jar: log4j-core-2.14.1.jar", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
             [_vuln("CVE-2021-44228", "CRITICAL", 10.0)]),
        # no coordinates at all: the file name is all there is
        _dep("example-tools-1.0.jar", None, [_vuln("CVE-3")]),
        _dep("clean.jar", "pkg:maven/org.x/clean@1.0", []),
    ])
    deps = parse_dependency_check_json(path, ("com.example",))
    assert [d["artifact_id"] for d in deps] == ["log4j-core"]
    assert deps[0]["version"] == "2.14.1" and deps[0]["highest_severity"] == "CRITICAL"


def test_version_from_file_name_when_no_purl(tmp_path):
    path = _report(tmp_path, [_dep("parent.jar: commons-text-1.9.jar", None, [_vuln("CVE-2022-42889")])])
    dep = parse_dependency_check_json(path, ())[0]
    assert (dep["artifact_id"], dep["version"], dep["group_id"]) == ("commons-text", "1.9", "")


def test_identification_confidence_and_related_files(tmp_path):
    path = _report(tmp_path, [_dep(
        "netty-transport-4.1.0.jar", "pkg:maven/io.netty/netty-transport@4.1.0", [_vuln("CVE-9")],
        confidence=["LOW", "MEDIUM"],
        related=[{"fileName": "netty-codec-4.1.0.jar", "packageIds": [{"id": "pkg:maven/io.netty/netty-codec@4.1.0"}]},
                 {"fileName": "example-netty-ext.jar", "packageIds": [{"id": "pkg:maven/com.example/netty-ext@1"}]}])])
    dep = parse_dependency_check_json(path, ("com.example",))[0]
    assert dep["identification_confidence"] == "MEDIUM"
    assert dep["related_files"] == ["netty-codec-4.1.0.jar"]
    assert count_total_dependencies(path) == 3


def test_not_a_dependency_check_report(tmp_path):
    path = tmp_path / "other.json"
    path.write_text('{"x": 1}', encoding="utf-8")
    import pytest
    with pytest.raises(ValueError):
        parse_dependency_check_json(path)
