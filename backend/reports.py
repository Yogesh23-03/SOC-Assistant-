"""Plain-text investigation reports and a small paginated PDF renderer."""
import textwrap
from backend.cases import get_case


def report_text(case):
    alert = case['alert']
    lines = ['SOC investigation report', f"Generated: {case['generated_at']}", f"Case: {case['alert_id']}",
             f"Rule: {alert.get('rule_name', 'Unknown')}", f"Host: {alert.get('host') or 'Unknown'}",
             f"Source: {alert.get('source_ip') or 'Unknown'}", f"Analysis status: {case['status']}", '']
    for run in case['runs']:
        result = run['result']
        verdict = result.get('verdict') or {}
        lines += [f"Investigation {run['run_id']} ({run['started_at']})", f"Status: {run['status']}",
                  f"Verdict: {verdict.get('label', 'unavailable')} | Confidence: {verdict.get('confidence', 'unavailable')}",
                  f"Reason: {verdict.get('reasoning', run.get('error') or '')}"]
        for finding in result.get('findings', []):
            lines.append(f"Evidence [{finding['source']}]: {finding['detail']}")
        lines.append('')
    lines.append('Human decisions and proposed actions')
    for proposal in case['proposals']:
        lines += [f"{proposal['proposal_id']}: {proposal['action']} {proposal['target']} - {proposal['status']}",
                  f"Analyst: {proposal.get('decision_by') or 'none'} | Decision time: {proposal.get('decision_at') or 'none'}",
                  f"Reason: {proposal['reason']}"]
    lines += ['', 'Firewall execution records']
    lines += [f"{b['target']}: {b['status']} | Applied: {b['blocked_at']} | Expires: {b['expires_at']}" for b in case['blocks']]
    if not case['blocks']:
        lines.append('No recorded firewall application. Approval alone does not mean execution.')
    lines += ['', f"Recorded tool calls: {len(case['tools'])}", '', 'Original log (untrusted evidence)', alert.get('log_text', '')]
    return '\n'.join(lines)


def render_pdf(text):
    # Built-in Helvetica uses WinAnsi. Replace unsupported glyphs; never interpret
    # evidence as PDF commands, markup, JavaScript or links.
    lines = []
    for line in text.splitlines():
        lines.extend(textwrap.wrap(line, width=95, replace_whitespace=True) or [''])
    pages = [lines[i:i+48] for i in range(0, len(lines), 48)] or [[]]
    objects = [b'', b'', b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>']
    kids = []
    for number, page in enumerate(pages, 1):
        page_id = len(objects) + 1
        stream_id = page_id + 1
        kids.append(f'{page_id} 0 R')
        objects.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {stream_id} 0 R >>'.encode())
        commands = ['BT /F1 10 Tf 42 752 Td 14 TL']
        for line in page + ['', f'Page {number} of {len(pages)}']:
            escaped = line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            commands.append(f'({escaped}) Tj T*')
        commands.append('ET')
        stream = '\n'.join(commands).encode('cp1252', errors='replace')
        objects.append(f'<< /Length {len(stream)} >>\nstream\n'.encode() + stream + b'\nendstream')
    objects[0] = b'<< /Type /Catalog /Pages 2 0 R >>'
    objects[1] = f'<< /Type /Pages /Kids [{" ".join(kids)}] /Count {len(pages)} >>'.encode()
    pdf = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f'{i} 0 obj\n'.encode() + obj + b'\nendobj\n')
    xref = len(pdf)
    pdf.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:
        pdf.extend(f'{offset:010d} 00000 n \n'.encode())
    pdf.extend(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(pdf)
