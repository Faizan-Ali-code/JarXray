"""Standalone, styled dependency risk report (HTML).

This is a software composition analysis (SCA) summary of dependency-check's
findings - not a penetration test: nothing was exploited or tested live.
"""
from datetime import datetime
from pathlib import Path

from . import TOOL_VERSION
from .ai_lookup import PLACEHOLDER_COMMENT_PREFIXES
from .fix_lookup import FIX_AVAILABLE, NO_FIX, NOT_IN_OSV
from .report_ods import format_cvss
from .severity import severity_rank

_SEVERITY_STYLE = {
    "CRITICAL": {"bg": "#dc2626", "light": "#fee2e2", "text": "#7f1d1d"},
    "HIGH":     {"bg": "#ea580c", "light": "#ffedd5", "text": "#7c2d12"},
    "MEDIUM":   {"bg": "#d97706", "light": "#fef3c7", "text": "#78350f"},
    "LOW":      {"bg": "#2563eb", "light": "#dbeafe", "text": "#1e3a8a"},
    "UNKNOWN":  {"bg": "#64748b", "light": "#f1f5f9", "text": "#334155"},
}

_STATUS_COLOR = {
    FIX_AVAILABLE: "#16a34a",
    NO_FIX: "#dc2626",
    NOT_IN_OSV: "#b45309",
}

_OSV_MARK = {
    True: '<span class="osv osv-yes" title="OSV lists this vulnerability for this exact package and version">'
          'OSV &#10003;</span>',
    False: '<span class="osv osv-no" title="OSV does not list it for this package: dependency-check matched the '
           'product by CPE name only - possible false positive">not in OSV</span>',
    None: "",
}

def _html_escape(value: str) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _sev_style(sev: str) -> dict:
    return _SEVERITY_STYLE.get(sev, _SEVERITY_STYLE["UNKNOWN"])


def _build_cve_cell(vulnerabilities: list) -> str:
    if not vulnerabilities:
        return '<span class="muted">—</span>'

    # Small count pills, one per severity present, most severe first
    counts = {}
    for v in vulnerabilities:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1
    ordered_severities = sorted(counts.keys(), key=severity_rank, reverse=True)
    pills = "".join(
        f'<span class="count-pill" style="background:{_sev_style(sev)["light"]};color:{_sev_style(sev)["text"]}">'
        f'{counts[sev]} {_html_escape(sev)}</span>'
        for sev in ordered_severities
    )

    def cve_line(v):
        desc = _html_escape(v["description"])[:400]
        style = _sev_style(v["severity"])
        return (
            f'<div class="cve-row" title="{desc}">'
            f'<span class="cve-id">{_html_escape(v["cve_id"])}</span>'
            f'<span class="sev-badge" style="background:{style["bg"]}">{_html_escape(v["severity"])}</span>'
            f'{_OSV_MARK.get(v.get("osv_confirmed"), "")}'
            f'<span class="cvss">{_html_escape(format_cvss(v))}</span>'
            f'</div>'
        )

    lines_html = "".join(cve_line(v) for v in vulnerabilities)

    if len(vulnerabilities) <= 3:
        # Small enough to just show directly, no need to hide anything
        return f'<div class="pill-row">{pills}</div><div class="cve-list">{lines_html}</div>'

    return (
        f'<details class="cve-details">'
        f'<summary><div class="pill-row">{pills}</div>'
        f'<span class="toggle-hint">{len(vulnerabilities)} CVEs — click to view all</span></summary>'
        f'<div class="cve-list">{lines_html}</div>'
        f'</details>'
    )


def _build_related_cell(related: list) -> str:
    """Jars dependency-check grouped with this one as the same library."""
    if not related:
        return ""
    items = "".join(f"<li>{_html_escape(name)}</li>" for name in related)
    label = f"+ {len(related)} related jar{'s' if len(related) != 1 else ''}"
    return (f'<details class="related"><summary>{label}</summary>'
            f'<ul class="related-list">{items}</ul></details>')


def _confidence_note(dep: dict) -> str:
    level = dep.get("identification_confidence") or ""
    if level not in ("LOW", "MEDIUM"):
        return ""
    return (f'<div class="confidence" title="How sure dependency-check is that it identified the right product. '
            f'LOW/MEDIUM matches are the usual source of false positives.">CPE match confidence: '
            f'{_html_escape(level)}</div>')


def _triage_summary(triage: dict) -> str:
    if not triage or not triage.get("looked_up"):
        return ""
    confirmed, unconfirmed, unknown = triage["confirmed"], triage["unconfirmed"], triage["unknown"]
    total = confirmed + unconfirmed + unknown
    text = f"<strong>{confirmed}</strong> of {total} CVE findings confirmed by OSV for the exact package"
    if unconfirmed:
        text += (f" &nbsp;|&nbsp; <strong>{unconfirmed}</strong> not listed by OSV - review them as possible "
                 f"false positives of dependency-check's CPE matching")
    if unknown:
        text += f" &nbsp;|&nbsp; {unknown} could not be checked"
    return f'<div class="exec-summary triage">{text}</div>'


def build_risk_html_report(dependencies: list, html_path: Path, project_name: str, app_code: str,
                           environment: str, total_scanned: int = 0, triage: dict = None) -> None:
    """total_scanned counts jar files (related ones included), the same unit
    as the affected-file count below, so 'clean' is a real subtraction.
    triage: the OSV confirmation counts from fix_lookup.apply_fix_lookup."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_cves = 0
    for d in dependencies:
        counts[d["highest_severity"]] = counts.get(d["highest_severity"], 0) + 1
        total_cves += len(d["vulnerabilities"])

    generated_at = datetime.now().strftime("%d-%m-%Y %H:%M")
    vulnerable_count = len(dependencies)
    affected_files = sum(1 + len(d.get("related_files") or []) for d in dependencies)
    clean_count = max(total_scanned - affected_files, 0) if total_scanned else None

    rows_html = []
    for d in dependencies:
        sev = d["highest_severity"]
        style = _sev_style(sev)

        # These three can arrive as None from a hand-edited AI cache entry,
        # so coerce before doing anything string-shaped with them.
        status = str(d.get("status") or "")
        status_color = _STATUS_COLOR.get(status, "#64748b")

        recommended = str(d.get("recommended_version") or "NA")
        if recommended == "NA":
            recommended_html = '<span class="muted">—</span>'
        else:
            recommended_html = f'<span class="recommended-version">{_html_escape(recommended)}</span>'

        comment = str(d.get("comments") or "")
        comment_class = "muted-italic" if comment.startswith(PLACEHOLDER_COMMENT_PREFIXES) else ""

        rows_html.append(f"""
        <tr style="border-left: 4px solid {style['bg']}">
          <td><div class="dep-name">{_html_escape(d['file_name'])}</div>{_confidence_note(d)}{_build_related_cell(d.get('related_files'))}</td>
          <td><span class="sev-badge" style="background:{style['bg']}">{_html_escape(sev)}</span></td>
          <td class="cve-cell">{_build_cve_cell(d['vulnerabilities'])}</td>
          <td>{recommended_html}</td>
          <td><span class="status-pill" style="background:{status_color}">{_html_escape(status)}</span></td>
          <td class="{comment_class}">{_html_escape(comment) if comment else '<span class="muted">—</span>'}</td>
        </tr>""")

    summary_cards = "".join(
        f"""<div class="card" style="border-top: 4px solid {_SEVERITY_STYLE[sev]['bg']}">
              <div class="card-count" style="color:{_SEVERITY_STYLE[sev]['bg']}">{counts.get(sev, 0)}</div>
              <div class="card-label">{sev}</div>
            </div>"""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    stat_line_parts = [f"<strong>{vulnerable_count}</strong> vulnerable dependencies"]
    if affected_files > vulnerable_count:
        stat_line_parts[0] += f" (<strong>{affected_files}</strong> jar files incl. related)"
    if total_scanned:
        stat_line_parts.append(f"out of <strong>{total_scanned}</strong> scanned")
        if clean_count is not None:
            stat_line_parts.append(f"<strong>{clean_count}</strong> clean")
    stat_line_parts.append(f"<strong>{total_cves}</strong> total CVEs identified")
    exec_summary = " &nbsp;|&nbsp; ".join(stat_line_parts)

    risk_note = ""
    if counts.get("CRITICAL", 0) > 0:
        risk_note = (f'<div class="risk-banner risk-critical">'
                     f'{counts["CRITICAL"]} CRITICAL severity finding(s) require immediate remediation.</div>')
    elif counts.get("HIGH", 0) > 0:
        risk_note = (f'<div class="risk-banner risk-high">'
                     f'{counts["HIGH"]} HIGH severity finding(s) should be prioritized for remediation.</div>')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dependency Risk Report - {_html_escape(project_name)}</title>
<style>
  :root {{
    --navy: #0f2942;
    --navy-light: #1e3a5f;
    --accent: #3b82f6;
    --bg: #eef1f5;
    --card-bg: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --text-muted: #64748b;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Segoe UI', -apple-system, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg); color: var(--text); margin: 0; padding: 0; font-size: 14px;
  }}
  .header {{
    background: linear-gradient(135deg, var(--navy) 0%, var(--navy-light) 100%);
    color: white; padding: 36px 44px;
  }}
  .header .tag {{
    display: inline-block; background: rgba(255,255,255,0.15); padding: 3px 10px;
    border-radius: 3px; font-size: 11px; letter-spacing: 1.5px; font-weight: 600;
    margin-bottom: 12px;
  }}
  .header h1 {{ margin: 0 0 6px 0; font-size: 26px; font-weight: 600; }}
  .header .subtitle {{ font-size: 13px; opacity: 0.75; margin-bottom: 18px; }}
  .header .meta {{ font-size: 13px; opacity: 0.92; display: flex; gap: 24px; flex-wrap: wrap; }}
  .header .meta b {{ font-weight: 600; }}
  .container {{ padding: 32px 44px 44px 44px; max-width: 1400px; margin: 0 auto; }}

  .risk-banner {{
    padding: 12px 18px; border-radius: 6px; font-size: 13px; font-weight: 600;
    margin-bottom: 20px; color: white;
  }}
  .risk-critical {{ background: #dc2626; }}
  .risk-high {{ background: #ea580c; }}

  .exec-summary {{
    background: var(--card-bg); border-radius: 8px; padding: 18px 24px; margin-bottom: 24px;
    box-shadow: 0 1px 2px rgba(15,41,66,0.06); font-size: 13.5px; color: var(--text-muted);
    border: 1px solid var(--border);
  }}
  .exec-summary strong {{ color: var(--text); font-size: 15px; }}

  .cards {{ display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }}
  .card {{
    background: var(--card-bg); border-radius: 8px; padding: 18px 28px;
    box-shadow: 0 1px 3px rgba(15,41,66,0.08); min-width: 130px; text-align: center;
    border: 1px solid var(--border);
  }}
  .card-count {{ font-size: 30px; font-weight: 700; line-height: 1.1; }}
  .card-label {{ font-size: 11px; letter-spacing: 1.2px; color: var(--text-muted); margin-top: 6px; font-weight: 600; }}

  .table-wrap {{
    background: var(--card-bg); border-radius: 8px; overflow: hidden;
    box-shadow: 0 1px 3px rgba(15,41,66,0.08); border: 1px solid var(--border);
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    background: var(--navy); color: white; text-align: left; padding: 13px 16px;
    font-size: 11.5px; letter-spacing: 0.6px; text-transform: uppercase; font-weight: 600;
    position: sticky; top: 0;
  }}
  tbody td {{ padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:nth-child(even) {{ background: #fafbfc; }}
  tbody tr:hover {{ background: #f0f4f8; }}
  .dep-name {{ font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12.5px; font-weight: 600; word-break: break-word; }}
  .related {{ margin-top: 6px; }}
  .related summary {{ cursor: pointer; font-size: 11.5px; color: var(--accent); font-weight: 600; list-style: none; }}
  .related summary::-webkit-details-marker {{ display: none; }}
  .related summary::before {{ content: "▸ "; font-size: 11px; }}
  .related[open] summary::before {{ content: "▾ "; }}
  .related-list {{
    margin: 6px 0 0 0; padding-left: 16px; font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 11.5px; color: var(--text-muted); word-break: break-word;
  }}

  .sev-badge, .status-pill {{
    display: inline-block; padding: 3px 10px; border-radius: 12px; color: white;
    font-size: 10.5px; font-weight: 700; letter-spacing: 0.4px; white-space: nowrap;
  }}
  .count-pill {{
    display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10.5px;
    font-weight: 700; margin: 0 4px 4px 0;
  }}
  .pill-row {{ margin-bottom: 4px; }}
  .toggle-hint {{ font-size: 11.5px; color: var(--accent); font-weight: 600; cursor: pointer; }}
  .cve-details summary {{ cursor: pointer; list-style: none; }}
  .cve-details summary::-webkit-details-marker {{ display: none; }}
  .cve-details summary::before {{ content: "▸ "; color: var(--accent); font-size: 11px; }}
  .cve-details[open] summary::before {{ content: "▾ "; }}
  .cve-list {{ margin-top: 8px; max-height: 260px; overflow-y: auto; padding-right: 4px; }}
  .cve-row {{
    display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 12px;
    border-bottom: 1px dashed var(--border);
  }}
  .cve-row:last-child {{ border-bottom: none; }}
  .cve-id {{ font-family: 'Cascadia Code', 'Consolas', monospace; min-width: 130px; color: var(--text); }}
  .cvss {{ color: var(--text-muted); font-size: 11px; margin-left: auto; }}
  .recommended-version {{
    font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px; font-weight: 600;
    color: #15803d; background: #f0fdf4; padding: 2px 8px; border-radius: 4px;
  }}
  .osv {{ font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 8px; white-space: nowrap; }}
  .osv-yes {{ background: #dcfce7; color: #166534; }}
  .osv-no {{ background: #fef3c7; color: #92400e; }}
  .confidence {{ font-size: 11px; color: #92400e; margin-top: 4px; }}
  .muted {{ color: #94a3b8; }}
  .muted-italic {{ color: #94a3b8; font-style: italic; font-size: 12.5px; }}

  .footer {{ padding: 22px 44px; font-size: 12px; color: var(--text-muted); text-align: center; }}

  @media print {{
    body {{ background: white; }}
    .card, .table-wrap, .exec-summary {{ box-shadow: none; border: 1px solid #ccc; }}
    thead th {{ position: static; }}
    /* A printed/PDF copy has to show every CVE, not just the collapsed
       summary. A closed <details> hides its content with content-visibility
       on an internal slot, so forcing display on the children is NOT enough
       on its own - ::details-content is what actually reveals it. Both rules
       are kept: the older one still helps engines that used display:none,
       and the print-time script below covers browsers with neither. */
    details::details-content {{ content-visibility: visible !important; }}
    details:not([open]) > *:not(summary) {{ display: block !important; }}
    .cve-details summary::before, .related summary::before {{ content: ""; }}
    .cve-list {{ max-height: none; overflow: visible; }}
  }}
</style>
</head>
<body>
  <div class="header">
    <div class="tag">CONFIDENTIAL — INTERNAL USE ONLY</div>
    <h1>Dependency Risk Report</h1>
    <div class="subtitle">Software composition analysis of third-party components (OWASP Dependency-Check)</div>
    <div class="meta">
      <span><b>Project</b> &nbsp;{_html_escape(project_name)}</span>
      <span><b>App Code</b> &nbsp;{_html_escape(app_code)}</span>
      <span><b>Environment</b> &nbsp;{_html_escape(environment)}</span>
      <span><b>Generated</b> &nbsp;{generated_at}</span>
    </div>
  </div>
  <div class="container">
    {risk_note}
    <div class="exec-summary">{exec_summary}</div>
    {_triage_summary(triage)}
    <div class="cards">
      {summary_cards}
    </div>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Dependency</th>
          <th>Highest Severity</th>
          <th>CVE Details</th>
          <th>Recommended Version</th>
          <th>Status</th>
          <th>Comments</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows_html) if rows_html else '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:32px;">No vulnerable dependencies found</td></tr>'}
      </tbody>
    </table>
    </div>
  </div>
  <div class="footer">
    Generated by JarXray v{TOOL_VERSION} from the OWASP Dependency-Check scan output. This is a component inventory
    check, not a penetration test. Recommended versions come from OSV.dev advisories and Maven Central release data
    (the first release OSV lists no advisory for). Comments marked "AI note (unverified)" are AI-generated.
  </div>
<script>
// Belt and braces for Ctrl+P / Print to PDF: expand every collapsed list
// (CVEs and related jars) for the print, then put it back. The @media print
// rules above handle this on their own in current Chromium/Edge; this covers
// everything else.
(function () {{
  var reopened = [];
  window.addEventListener("beforeprint", function () {{
    reopened = [];
    document.querySelectorAll("details:not([open])").forEach(function (d) {{
      reopened.push(d);
      d.open = true;
    }});
  }});
  window.addEventListener("afterprint", function () {{
    reopened.forEach(function (d) {{ d.open = false; }});
    reopened = [];
  }});
}})();
</script>
</body>
</html>"""

    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html, encoding="utf-8")
