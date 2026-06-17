#!/usr/bin/env python3
import csv
import html
import os
import pathlib
import re
import zipfile
from datetime import datetime


LAB_DIR = pathlib.Path(os.environ.get("LANPILOT_LAB_DIR", pathlib.Path.home() / "lanpilot-audit-latest")).resolve()
REPORT_DIR = LAB_DIR / "06-report"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def read_csv(relative):
    path = LAB_DIR / relative
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_kv(relative):
    result = {}
    path = LAB_DIR / relative
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                result[key] = value
    return result


def esc(value):
    return html.escape(str(value or ""))


def render_table(rows, columns):
    if not rows:
        return '<p class="empty">No observations recorded for this section.</p>'
    header = "".join(f"<th>{esc(label)}</th>" for _, label in columns)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{esc(row.get(key, ''))}</td>" for key, _ in columns) + "</tr>")
    return f"<div class='table-wrap'><table><thead><tr>{header}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"


def build_html():
    summary = read_kv("00-scope/network-summary.txt")
    issues = read_csv("04-risk/network-issues-register.csv")
    assets = read_csv("02-assets/passive-arp-assets.csv")
    services = read_csv("03-services/reachable-open-ports.csv")
    risks = {"High": 0, "Medium": 0, "Low": 0}
    for issue in issues:
        if issue.get("severity") in risks:
            risks[issue["severity"]] += 1
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LANPilot Audit Report</title>
<style>
:root{{--ink:#17212b;--muted:#617080;--line:#d9e0e5;--paper:#fff;--bg:#f4f6f7;--high:#b42318;--medium:#b54708;--low:#175cd3;--accent:#167d72}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
header{{background:#17212b;color:#fff;padding:28px 32px}} header h1{{margin:0;font-size:26px;letter-spacing:0}} header p{{margin:5px 0 0;color:#c8d1d8}}
main{{max-width:1220px;margin:0 auto;padding:24px}} .metrics{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:24px}}
.metric{{background:var(--paper);border:1px solid var(--line);border-radius:6px;padding:16px}} .metric span{{display:block;color:var(--muted);font-size:12px;text-transform:uppercase}} .metric strong{{font-size:27px}}
section{{margin:0 0 28px}} h2{{font-size:18px;margin:0 0 10px}} .notice{{border-left:4px solid var(--accent);background:#edf8f6;padding:12px 14px;margin-bottom:24px}}
.table-wrap{{overflow:auto;border:1px solid var(--line);background:#fff}} table{{border-collapse:collapse;width:100%;min-width:760px}} th,td{{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} th{{background:#eef2f4;font-size:12px}} tr:last-child td{{border-bottom:0}}
.empty{{color:var(--muted);background:#fff;border:1px solid var(--line);padding:14px}} footer{{color:var(--muted);padding:0 32px 30px}} @media(max-width:760px){{.metrics{{grid-template-columns:repeat(2,1fr)}} main{{padding:14px}}}}
</style></head><body>
<header><h1>LANPilot Audit</h1><p>Authorized network security governance report · {esc(generated)}</p></header>
<main>
<div class="notice"><strong>Observation limits:</strong> Findings are point-in-time observations based on current ARP cache, ICMP reachability, and low-intensity common service checks.</div>
<div class="metrics">
<div class="metric"><span>High</span><strong style="color:var(--high)">{risks['High']}</strong></div>
<div class="metric"><span>Medium</span><strong style="color:var(--medium)">{risks['Medium']}</strong></div>
<div class="metric"><span>Low</span><strong style="color:var(--low)">{risks['Low']}</strong></div>
<div class="metric"><span>Passive assets</span><strong>{len(assets)}</strong></div>
</div>
<section><h2>Network Context</h2>{render_table([summary], [('audit_interface','Audit interface'),('local_cidr','Local CIDR'),('default_gateway','Gateway'),('reachable_client_count','Reachable clients'),('unreachable_client_count','Unreachable clients')])}</section>
<section><h2>Risk Register</h2>{render_table(issues, [('issue_id','ID'),('severity','Severity'),('asset','Asset'),('finding','Finding'),('recommended_action','Recommended action'),('status','Status')])}</section>
<section><h2>Open Services</h2>{render_table(services, [('ip','IP'),('port','Port'),('service','Service'),('version','Version'),('detected_at','Detected at')])}</section>
<section><h2>Passive Assets</h2>{render_table(assets, [('ip','IP'),('mac','MAC'),('interface','Interface'),('source','Source'),('last_seen','Last seen')])}</section>
</main><footer>LANPilot Audit provides observations and remediation guidance only. It does not modify network devices or clients.</footer>
</body></html>"""
    (REPORT_DIR / "lanpilot-audit-report.html").write_text(content, encoding="utf-8")


def xml_escape(value):
    return html.escape(str(value or ""), quote=False)


def col_name(number):
    result = ""
    while number:
        number, rem = divmod(number - 1, 26)
        result = chr(65 + rem) + result
    return result


def worksheet_xml(rows):
    xml_rows = []
    for r_idx, row in enumerate(rows, 1):
        cells = []
        for c_idx, value in enumerate(row, 1):
            ref = f"{col_name(c_idx)}{r_idx}"
            style = ' s="1"' if r_idx == 1 else ""
            cells.append(f'<c r="{ref}" t="inlineStr"{style}><is><t>{xml_escape(value)}</t></is></c>')
        xml_rows.append(f'<row r="{r_idx}">{"".join(cells)}</row>')
    width = max((len(row) for row in rows), default=1)
    cols = "".join(f'<col min="{i}" max="{i}" width="{18 if i < 4 else 34}" customWidth="1"/>' for i in range(1, width + 1))
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>{cols}</cols><sheetData>{"".join(xml_rows)}</sheetData><autoFilter ref="A1:{col_name(width)}{max(len(rows),1)}"/></worksheet>'''


def dict_rows(rows):
    if not rows:
        return [["No observations"]]
    headers = list(rows[0].keys())
    return [headers] + [[row.get(header, "") for header in headers] for row in rows]


def build_xlsx():
    summary = read_kv("00-scope/network-summary.txt")
    sheets = [
        ("Executive", [["LANPilot Audit", "Authorized network security governance report"], ["Generated", datetime.now().astimezone().isoformat()], ["Lab directory", str(LAB_DIR)]] + [[k, v] for k, v in summary.items()]),
        ("Issues", dict_rows(read_csv("04-risk/network-issues-register.csv"))),
        ("Assets", dict_rows(read_csv("02-assets/passive-arp-assets.csv"))),
        ("Services", dict_rows(read_csv("03-services/reachable-open-ports.csv"))),
        ("Asset Inventory", dict_rows(read_csv("02-assets/asset-inventory.csv"))),
        ("Exposure Matrix", dict_rows(read_csv("03-services/service-exposure-matrix.csv"))),
        ("Web Baseline", dict_rows(read_csv("03-services/web-baseline.csv"))),
        ("TLS Certificates", dict_rows(read_csv("03-services/tls-certificates.csv"))),
        ("Remediation", dict_rows(read_csv("05-remediation/remediation-authority-matrix.csv"))),
        ("Tracking", dict_rows(read_csv("05-remediation/remediation-tracking.csv"))),
    ]
    output = REPORT_DIR / "lanpilot-audit-report.xlsx"
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as book:
        book.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, len(sheets)+1)) + '</Types>')
        book.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        book.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + "".join(f'<sheet name="{xml_escape(name)}" sheetId="{i}" r:id="rId{i}"/>' for i, (name, _) in enumerate(sheets, 1)) + '</sheets></workbook>')
        book.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets)+1)) + f'<Relationship Id="rId{len(sheets)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        book.writestr("xl/styles.xml", '<?xml version="1.0" encoding="UTF-8"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Aptos"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Aptos"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF17212B"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')
        for index, (_, rows) in enumerate(sheets, 1):
            book.writestr(f"xl/worksheets/sheet{index}.xml", worksheet_xml(rows))


if __name__ == "__main__":
    if not LAB_DIR.exists():
        raise SystemExit(f"Lab directory not found: {LAB_DIR}")
    build_html()
    build_xlsx()
    print(f"HTML report: {REPORT_DIR / 'lanpilot-audit-report.html'}")
    print(f"Excel report: {REPORT_DIR / 'lanpilot-audit-report.xlsx'}")
