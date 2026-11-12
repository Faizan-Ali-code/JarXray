"""Which jars are internal, and that third-party code inside internal archives is still scanned."""
import pytest

from conftest import jar_bytes, make_jar, pom
from jarxray.jar_classifier import base_file_name, group_id_is_internal, inspect_jar, separate_jars

LOG4J = jar_bytes({**pom("org.apache.logging.log4j", "log4j-core", "2.14.1"),
                   "org/apache/logging/log4j/core/Logger.class": b"\xca\xfe"})
INTERNAL_LIB = jar_bytes({**pom("com.example", "common"), "com/example/common/Util.class": b"\xca\xfe"})


@pytest.mark.parametrize("entries,expected", [
    ({"com/example/app/Main.class": b""}, "classes"),
    ({"BOOT-INF/classes/com/example/app/Main.class": b""}, "classes"),
    ({"WEB-INF/classes/com/example/web/Servlet.class": b""}, "classes"),
    ({**pom("com.example.pay", "hub"), "io/hub/Client.class": b""}, "maven groupId"),  # coordinates != packages
])
def test_internal_by_content(tmp_path, prefixes, entries, expected):
    info = inspect_jar(make_jar(tmp_path / "anything.jar", entries), prefixes)
    assert info.internal and info.reason == expected


@pytest.mark.parametrize("name,entries", [
    ("example-utils.jar", {"org/thirdparty/Util.class": b""}),            # name alone is not enough
    ("lib.example.jar", {**pom("org.thirdparty", "x")}),
    ("shade.jar", {"shaded/com/example/Copy.class": b""}),               # path must START with the package
    ("corp.jar", {**pom("com.examplecorp", "x"), "com/examplecorp/A.class": b""}),  # com.example != com.examplecorp
])
def test_third_party_jars_are_not_internal(tmp_path, prefixes, name, entries):
    assert not inspect_jar(make_jar(tmp_path / name, entries), prefixes).internal


def test_file_name_decides_only_without_classes_or_metadata(tmp_path, prefixes):
    resources = make_jar(tmp_path / "com.example-config.jar", {"config/app.properties": "a=1"})
    assert inspect_jar(resources, prefixes).reason == "file name"


def test_unreadable_jar_falls_back_to_file_name(tmp_path, prefixes):
    for name, internal in (("example-broken.jar", True), ("broken.jar", False)):
        (tmp_path / name).write_bytes(b"not a zip")
        assert inspect_jar(tmp_path / name, prefixes).internal is internal


def test_no_prefixes_means_nothing_is_internal(tmp_path):
    assert not inspect_jar(make_jar(tmp_path / "a.jar", {"com/example/A.class": b""}), ()).internal


def test_group_id_prefix_is_a_package_boundary():
    assert group_id_is_internal("com.example", ["com.example"])
    assert group_id_is_internal("com.example.pay", ["com.example"])
    assert not group_id_is_internal("com.examplecorp", ["com.example"])
    assert not group_id_is_internal("", ["com.example"])


def test_base_file_name():
    assert base_file_name("example-app.jar: log4j-core-2.14.1.jar") == "log4j-core-2.14.1.jar"
    assert base_file_name("app.jar (shaded: org.x:y:1.0)") == "app.jar"
    assert base_file_name("plain.jar") == "plain.jar"


def test_fat_jar_libraries_are_unpacked_for_the_scan(tmp_path, prefixes):
    app_dir = tmp_path / "apps" / "Orders"
    make_jar(app_dir / "orders-service.jar", {
        **pom("com.example", "orders-service"),
        "BOOT-INF/classes/com/example/orders/App.class": b"",
        "BOOT-INF/lib/log4j-core-2.14.1.jar": LOG4J,
        "BOOT-INF/lib/common-1.0.jar": INTERNAL_LIB,
    })
    make_jar(app_dir / "jackson-databind-2.9.0.jar", {**pom("com.fasterxml.jackson.core", "jackson-databind")})
    nested = tmp_path / "work" / "nested"

    sep = separate_jars(app_dir, prefixes, nested)

    assert sep.moved == 1 and sep.remaining == 1                       # the fat jar set aside, jackson stays
    assert [p.name for p in sep.nested_extracted] == ["log4j-core-2.14.1.jar"]  # internal bundled lib dropped
    assert sep.nested_extracted[0].parent.parent == nested
    assert sep.to_scan == 2
    assert (sep.internal_dir / "orders-service.jar").exists()


def test_without_nested_dir_nothing_is_unpacked(tmp_path, prefixes):
    app_dir = tmp_path / "app"
    make_jar(app_dir / "svc.jar", {"com/example/A.class": b"", "WEB-INF/lib/log4j.jar": LOG4J})
    assert separate_jars(app_dir, prefixes).nested_extracted == []


def test_shaded_internal_jar_stays_in_the_scan(tmp_path, prefixes):
    app_dir = tmp_path / "app"
    shaded = make_jar(app_dir / "client-all.jar", {
        **pom("com.example", "client"), **pom("org.apache.commons", "commons-text", "1.9"),
        "com/example/client/Api.class": b"", "com/example/shaded/org/apache/commons/text/StringSubstitutor.class": b""})
    info = inspect_jar(shaded, prefixes)
    assert info.shaded and info.third_party_groups == ("org.apache.commons",)
    sep = separate_jars(app_dir, prefixes, tmp_path / "nested")
    assert sep.kept_shaded == [shaded] and sep.moved == 0 and sep.leftover_internal == []
    assert sep.to_scan == 1


def test_empty_folder(tmp_path, prefixes):
    assert separate_jars(tmp_path, prefixes).to_scan == 0
