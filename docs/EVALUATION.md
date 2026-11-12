# Evaluation

What has been checked, how, and what is still open. Numbers here are only claimed where they were measured.

## 1. Automated tests (every push)

`tests/` (pytest, 72 tests) checks the logic that JarXray adds on top of Dependency-Check, without Java or network:

| Area | What is checked |
|---|---|
| Jar classification | internal by Maven groupId or package; a third-party jar named like the prefix is *not* internal; `com.example` does not match `com.examplecorp`; class paths must start with the package (shaded copies elsewhere do not count) |
| Bundled code | libraries in a fat jar's `BOOT-INF/lib` are unpacked and scanned, internal bundled libraries are dropped; a jar with shaded third-party classes stays in the scan |
| Report parsing | internal code is filtered by coordinates, so a library found *inside* an internal archive is still reported |
| Fix lookup | version ordering (`1.0-rc1 < 1.0 == 1.0.Final < 1.0.1`), OSV range evaluation, walking up when a fix is itself affected, staying on the `-jre` / `-android` flavour, recommending a newer release line when the current one gets no fix, caching, network failures |
| Command line | no shell; every argument quoted; values containing `"` or `%` refused; secrets masked in output, also in error messages |
| Credentials, scheduler | `${ENV}` references; `icacls` parsing for the SYSTEM-task permission check |
| Reports, AI notes | HTML escaping of scanner text, OSV markers, the AI can only add a labelled note, cache expiry |

## 2. Fix lookup against the live services (spot check, 12 Nov 2026)

`FixLookup.recommend()` run against api.osv.dev and repo1.maven.org for well-known vulnerable versions:

| Library in use | OSV-confirmed CVEs | Recommended | Note |
|---|---|---|---|
| log4j-core 2.14.1 | 8 (incl. CVE-2021-44228, -45046, -45105, -44832) | 2.25.4 | later advisories also need a newer release than the Log4Shell fixes |
| jackson-databind 2.9.8 | 60 | 2.18.11 | |
| commons-text 1.9 | 1 (CVE-2022-42889) | 1.10.0 | matches the Apache advisory |
| spring-core 5.3.18 | 2 | 6.2.19 | the 5.3 line has no open-source fix: flagged as a move to a newer line |
| guava 31.1-jre | 3 | 33.7.2-jre | an earlier version of the code recommended `-android`; fixed and covered by a test |

OSV data changes daily, so re-running this gives different numbers over time.

## 3. Still to do: comparison on real applications

Not yet measured: how often Dependency-Check's findings on real applications are false positives, and what it
misses. Planned method, to be filled in with real numbers:

1. **Targets** (public, with known vulnerable dependencies): an old OWASP WebGoat release jar (a Spring Boot fat
   jar, which also exercises the bundled-library unpacking) and an old Spring PetClinic build.
2. **JarXray run** with `INTERNAL_PACKAGES` set to the application's own package (e.g. `org.owasp.webgoat`).
3. **Reference run** with a second scanner that works from package coordinates instead of CPE names
   (OSV-Scanner or Trivy) on the same files.
4. **Compare** per dependency: CVEs both report, Dependency-Check only, reference only. Review every
   "Dependency-Check only" finding by hand (advisory text, affected versions) and label it true or false positive.
5. **Report**:

| Target | Jars scanned | DC findings | Confirmed by OSV | Not in OSV: true / false positive | Missed by DC |
|---|---|---|---|---|---|
| WebGoat … | | | | | |
| PetClinic … | | | | | |

The "not in OSV" marker is then judged by how many of those findings turn out to be false positives.
