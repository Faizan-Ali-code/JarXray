"""JarXray - separates internal jars (INTERNAL_PACKAGES), runs OWASP
dependency-check on the third-party rest, checks each finding and its fixed
version against OSV / Maven Central, and builds the analysis sheet and the
dependency risk report."""
TOOL_VERSION = "3.0"