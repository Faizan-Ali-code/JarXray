"""ODS analysis sheet: Dependency | Highest Severity | CVE Details | CPE Confidence | Recommended Version |
Status | Comments."""
from pathlib import Path

OSV_LABELS = {True: "OSV: confirmed", False: "OSV: not listed - possible false positive", None: ""}


def format_cvss(v: dict) -> str:
    if v.get("cvss_score") is None:
        return "CVSS n/a"
    version = f" {v['cvss_version']}" if v.get("cvss_version") else ""
    return f"CVSS{version} {v['cvss_score']}"


def format_cve_details(vulnerabilities: list) -> str:
    lines = []
    for v in vulnerabilities:
        osv = OSV_LABELS.get(v.get("osv_confirmed"), "")
        lines.append(f"{v['cve_id']} ({v['severity']}, {format_cvss(v)})" + (f" - {osv}" if osv else ""))
    return "\n".join(lines)


def format_dependency(dep: dict) -> str:
    """The jar, plus the jars dependency-check grouped with it as the same
    library - they carry the same CVEs and are upgraded together."""
    related = dep.get("related_files") or []
    if not related:
        return dep["file_name"]
    return "\n".join([dep["file_name"], f"+ {len(related)} related:"] + [f"  {name}" for name in related])


def build_ods_report(dependencies: list, ods_path: Path, project_name: str, app_code: str, environment: str) -> None:
    from odf.opendocument import OpenDocumentSpreadsheet
    from odf.table import Table, TableRow, TableCell, TableColumn
    from odf.text import P
    from odf.style import Style, TableColumnProperties, TableCellProperties, TextProperties

    doc = OpenDocumentSpreadsheet()

    header_style = Style(name="HeaderStyle", family="table-cell")
    header_style.addElement(TextProperties(fontweight="bold", color="#FFFFFF"))
    header_style.addElement(TableCellProperties(backgroundcolor="#1F4E78"))
    doc.automaticstyles.addElement(header_style)

    wrap_style = Style(name="WrapStyle", family="table-cell")
    wrap_style.addElement(TableCellProperties(wrapoption="wrap", verticalalign="top"))
    doc.automaticstyles.addElement(wrap_style)

    severity_styles = {}
    severity_colors = {
        "CRITICAL": "#FFC7CE",
        "HIGH": "#FFDDA1",
        "MEDIUM": "#FFF2A8",
        "LOW": "#D9E8FB",
    }
    for sev, color in severity_colors.items():
        st = Style(name=f"Sev{sev}", family="table-cell")
        st.addElement(TableCellProperties(backgroundcolor=color, wrapoption="wrap", verticalalign="top"))
        doc.automaticstyles.addElement(st)
        severity_styles[sev] = st

    col_width_style = Style(name="ColWide", family="table-column")
    col_width_style.addElement(TableColumnProperties(columnwidth="6cm"))
    doc.automaticstyles.addElement(col_width_style)

    table = Table(name="Dependency Analysis")
    headers = ["Dependency", "Highest Severity", "CVE Details", "CPE Confidence", "Recommended Version", "Status",
               "Comments"]
    for _ in headers:
        table.addElement(TableColumn(stylename=col_width_style))

    header_row = TableRow()
    for h in headers:
        cell = TableCell(stylename=header_style)
        cell.addElement(P(text=h))
        header_row.addElement(cell)
    table.addElement(header_row)

    for dep in dependencies:
        row = TableRow()
        sev = dep["highest_severity"]
        sev_style = severity_styles.get(sev, wrap_style)

        values = [
            format_dependency(dep),
            sev,
            format_cve_details(dep["vulnerabilities"]),
            dep.get("identification_confidence", ""),
            dep.get("recommended_version", "NA"),
            dep.get("status", ""),
            dep.get("comments", ""),
        ]
        for i, val in enumerate(values):
            cell_style = sev_style if i == 1 else wrap_style
            cell = TableCell(stylename=cell_style)
            for line in str(val).split("\n"):
                cell.addElement(P(text=line))
            row.addElement(cell)
        table.addElement(row)

    doc.spreadsheet.addElement(table)
    ods_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(ods_path))
