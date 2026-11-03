"""Optional email delivery of the generated reports for one application.

Controlled entirely by the EMAIL_* / SMTP_* keys in config.txt. Never raises -
the reports are already safely written to disk by the time this runs, so a
delivery failure is printed as a warning and the pipeline continues rather
than losing an otherwise-successful run.
"""
import re
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from .config import flag

IMPLICIT_TLS_PORT = 465

# The three standard reports. Extra OUTPUT_FORMAT files (CSV, XML, SARIF, the
# JSON) are kept in reports\ but not mailed: with them a message easily passes
# the 10 MB many relays accept, and then nobody gets anything.
EMAILED_REPORTS = ("dependency_check_html", "ods_report", "pentest_html")


def _tls_context(config: dict) -> ssl.SSLContext:
    # Verifies the server certificate and host name (smtplib's own default
    # does neither). On Windows this trusts the machine's certificate store,
    # which is where a company-internal CA is normally deployed.
    return ssl.create_default_context(cafile=config.get("SMTP_CA_BUNDLE", "").strip() or None)


def send_report_email(config: dict, project_name: str, app_code: str, environment: str,
                       result_paths: dict) -> None:
    if not flag(config, "EMAIL_ENABLED"):
        return

    # Commas or semicolons (Outlook's habit): smtplib reads "a@x; b@x" as ONE
    # address and silently delivers to a@x only.
    recipients = [r.strip() for r in re.split(r"[,;]", config.get("EMAIL_RECIPIENTS", "")) if r.strip()]
    if not recipients:
        print("  WARNING: EMAIL_ENABLED=yes but EMAIL_RECIPIENTS is empty in config.txt - skipping email.")
        return

    attachments = [p for p in (result_paths.get(key) for key in EMAILED_REPORTS)
                   if isinstance(p, Path) and p.exists()]
    if not attachments:
        print("  WARNING: no report files available to attach - skipping email.")
        return

    server_host = config.get("SMTP_SERVER", "").strip()
    if not server_host:
        print("  WARNING: EMAIL_ENABLED=yes but SMTP_SERVER is empty in config.txt - skipping email.")
        return

    subject_prefix = config.get("EMAIL_SUBJECT_PREFIX", "[Dependency-Check Automation]").strip()
    msg = EmailMessage()
    msg["Subject"] = f"{subject_prefix} {project_name} / {app_code} / {environment}"
    msg["From"] = config.get("EMAIL_FROM", "").strip() or config.get("SMTP_USERNAME", "").strip() or "depcheck-automation@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(
        "Dependency-check automation run completed.\n\n"
        f"Project: {project_name}\n"
        f"Application Code: {app_code}\n"
        f"Environment: {environment}\n\n"
        "The generated reports are attached:\n"
        + "\n".join(f"  - {p.name}" for p in attachments)
    )

    for path in attachments:
        data = path.read_bytes()
        maintype, subtype = ("text", "html") if path.suffix.lower() == ".html" else ("application", "octet-stream")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=path.name)

    try:
        port = int(config.get("SMTP_PORT", "587") or "587")
    except ValueError:
        port = 587
    username = config.get("SMTP_USERNAME", "").strip()
    password = config.get("SMTP_PASSWORD", "").strip()

    try:
        if port == IMPLICIT_TLS_PORT:
            # SMTPS: the server expects a TLS handshake before any SMTP
            # greeting, so a plain connection would just sit until timeout.
            server = smtplib.SMTP_SSL(server_host, port, timeout=30, context=_tls_context(config))
        else:
            server = smtplib.SMTP(server_host, port, timeout=30)
        with server:
            if port != IMPLICIT_TLS_PORT and flag(config, "SMTP_USE_TLS", "yes"):
                server.starttls(context=_tls_context(config))
            if username:
                server.login(username, password)
            server.send_message(msg)
        print(f"  Emailed reports to: {', '.join(recipients)}")
    except Exception as exc:
        print(f"  WARNING: email delivery failed ({exc}) - reports were still saved to disk above.")
