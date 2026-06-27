from .models import Finding


def redact_content(content: str, findings: list[Finding]) -> str:
    if not findings:
        return content

    pieces: list[str] = []
    cursor = 0
    for finding in sorted(findings, key=lambda item: item.start):
        if finding.start < cursor:
            continue
        pieces.append(content[cursor:finding.start])
        pieces.append(finding.redaction_token)
        cursor = finding.end
    pieces.append(content[cursor:])
    return "".join(pieces)

