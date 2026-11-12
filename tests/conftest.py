"""Shared helpers. No dependency-check, Java, network or Windows tools are needed: jars are built on the fly,
and OSV / Maven Central / OpenAI / icacls are replaced by fakes."""
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def make_jar(path: Path, entries: dict) -> Path:
    """A zip file with the given {entry name: bytes or str} content."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content.encode("utf-8") if isinstance(content, str) else content)
    return path


def jar_bytes(entries: dict) -> bytes:
    """A jar as bytes, to nest inside another archive."""
    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def pom(group: str, artifact: str, version: str = "1.0") -> dict:
    """Maven metadata entries the way the maven-jar-plugin writes them."""
    base = f"META-INF/maven/{group}/{artifact}/"
    return {base + "pom.properties": f"groupId={group}\nartifactId={artifact}\nversion={version}\n",
            base + "pom.xml": f"<project><groupId>{group}</groupId><artifactId>{artifact}</artifactId></project>"}


class FakeHttp:
    """Answers OSV queries from {(package, version): [vulns]} and Maven metadata from {(group, artifact): [versions]}."""

    def __init__(self, osv=None, maven=None, fail=False):
        self.osv, self.maven, self.fail = osv or {}, maven or {}, fail
        self.calls = []

    def __call__(self, url, body=None):
        self.calls.append((url, body))
        if self.fail:
            from jarxray.fix_lookup import FixLookupError
            raise FixLookupError("network unreachable")
        if body is not None:  # OSV query
            key = (body["package"]["name"], body["version"])
            return json.dumps({"vulns": self.osv.get(key, [])}).encode()
        for (group, artifact), versions in self.maven.items():
            if url.endswith(f"/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"):
                items = "".join(f"<version>{v}</version>" for v in versions)
                return f"<metadata><versioning><versions>{items}</versions></versioning></metadata>".encode()
        return b""  # 404


def osv_vuln(vuln_id, package, events, aliases=()):
    return {"id": vuln_id, "aliases": list(aliases),
            "affected": [{"package": {"ecosystem": "Maven", "name": package},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


@pytest.fixture
def prefixes():
    return ("com.example",)
