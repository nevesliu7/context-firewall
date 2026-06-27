import re
from dataclasses import dataclass
from math import log2
from hashlib import sha256

from .models import Finding, FindingType


@dataclass(frozen=True)
class DetectionRule:
    label: str
    type: FindingType
    pattern: re.Pattern[str]
    severity: str
    confidence: float
    token: str


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


RULES: list[DetectionRule] = [
    DetectionRule(
        label="Email Address",
        type=FindingType.pii,
        pattern=_compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
        severity="medium",
        confidence=0.96,
        token="EMAIL",
    ),
    DetectionRule(
        label="US Phone Number",
        type=FindingType.pii,
        pattern=_compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
        severity="medium",
        confidence=0.86,
        token="PHONE",
    ),
    DetectionRule(
        label="US Social Security Number",
        type=FindingType.regulated,
        pattern=_compile(r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
        severity="critical",
        confidence=0.95,
        token="SSN",
    ),
    DetectionRule(
        label="Credit Card Number",
        type=FindingType.regulated,
        pattern=_compile(r"\b(?:\d[ -]*?){13,19}\b"),
        severity="critical",
        confidence=0.72,
        token="CARD",
    ),
    DetectionRule(
        label="AWS Access Key",
        type=FindingType.secret,
        pattern=_compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        severity="critical",
        confidence=0.98,
        token="AWS_ACCESS_KEY",
    ),
    DetectionRule(
        label="OpenAI API Key",
        type=FindingType.secret,
        pattern=_compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        severity="critical",
        confidence=0.98,
        token="OPENAI_KEY",
    ),
    DetectionRule(
        label="Slack Token",
        type=FindingType.secret,
        pattern=_compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        severity="critical",
        confidence=0.96,
        token="SLACK_TOKEN",
    ),
    DetectionRule(
        label="GitHub Token",
        type=FindingType.secret,
        pattern=_compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b"),
        severity="critical",
        confidence=0.97,
        token="GITHUB_TOKEN",
    ),
    DetectionRule(
        label="Google API Key",
        type=FindingType.secret,
        pattern=_compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        severity="critical",
        confidence=0.96,
        token="GOOGLE_API_KEY",
    ),
    DetectionRule(
        label="Stripe Secret Key",
        type=FindingType.secret,
        pattern=_compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{20,}\b"),
        severity="critical",
        confidence=0.97,
        token="STRIPE_SECRET_KEY",
    ),
    DetectionRule(
        label="JWT",
        type=FindingType.secret,
        pattern=_compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity="high",
        confidence=0.92,
        token="JWT",
    ),
    DetectionRule(
        label="Private Key Block",
        type=FindingType.secret,
        pattern=_compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        severity="critical",
        confidence=0.99,
        token="PRIVATE_KEY",
    ),
    DetectionRule(
        label="Password Assignment",
        type=FindingType.secret,
        pattern=_compile(r"\b(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*[\"']?[^\"'\s]{8,}"),
        severity="high",
        confidence=0.82,
        token="CREDENTIAL",
    ),
    DetectionRule(
        label="Access Token Field",
        type=FindingType.secret,
        pattern=_compile(r"\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[\"']?\s*[:=]\s*[\"'][^\"']{12,}[\"']"),
        severity="high",
        confidence=0.87,
        token="TOKEN_FIELD",
    ),
    DetectionRule(
        label="Internal IPv4 Address",
        type=FindingType.confidential,
        pattern=_compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
        severity="medium",
        confidence=0.74,
        token="INTERNAL_IP",
    ),
    DetectionRule(
        label="Confidential Business Context",
        type=FindingType.confidential,
        pattern=_compile(r"\b(?:confidential|do not distribute|internal only|board deck|term sheet|acquisition|layoff plan|salary band|performance review)\b"),
        severity="high",
        confidence=0.78,
        token="CONFIDENTIAL",
    ),
    DetectionRule(
        label="Prompt Injection",
        type=FindingType.prompt_injection,
        pattern=_compile(r"\b(?:ignore previous instructions|reveal your system prompt|developer message|exfiltrate|bypass policy|disable safety|act as unrestricted)\b"),
        severity="high",
        confidence=0.9,
        token="PROMPT_INJECTION",
    ),
    DetectionRule(
        label="Source Code Secret Context",
        type=FindingType.source_code,
        pattern=_compile(r"\b(?:AWS_SECRET_ACCESS_KEY|DATABASE_URL|BEGIN PRIVATE KEY|Authorization:\s*Bearer|process\.env\.)\b"),
        severity="high",
        confidence=0.84,
        token="CODE_SECRET_CONTEXT",
    ),
]


def _preview(value: str) -> str:
    value = value.replace("\n", " ")
    if len(value) <= 12:
        return value[:2] + "***" + value[-2:]
    return value[:4] + "***" + value[-4:]


def _stable_token(label: str, value: str) -> str:
    digest = sha256(f"{label}:{value}".encode("utf-8")).hexdigest()[:8]
    return f"[REDACTED_{label}_{digest}]"


def detect_findings(content: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[int, int, str]] = set()

    for rule in RULES:
        for match in rule.pattern.finditer(content):
            value = match.group(0)
            if rule.label == "Credit Card Number" and not _passes_luhn(value):
                continue
            key = (match.start(), match.end(), rule.label)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    type=rule.type,
                    label=rule.label,
                    value_preview=_preview(value),
                    start=match.start(),
                    end=match.end(),
                    confidence=rule.confidence,
                    severity=rule.severity,  # type: ignore[arg-type]
                    redaction_token=_stable_token(rule.token, value),
                )
            )

    findings.extend(_detect_high_entropy_assignments(content, seen))
    findings.sort(key=lambda finding: (finding.start, finding.end))
    return _dedupe_overlaps(findings)


def _severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}[severity]


def _passes_luhn(value: str) -> bool:
    digits = [int(char) for char in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _detect_high_entropy_assignments(content: str, seen: set[tuple[int, int, str]]) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r"\b(?:secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{24,})[\"']?",
        re.IGNORECASE,
    )
    for match in pattern.finditer(content):
        value = match.group(1)
        if _shannon_entropy(value) < 3.7:
            continue
        key = (match.start(1), match.end(1), "High Entropy Secret")
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                type=FindingType.secret,
                label="High Entropy Secret",
                value_preview=_preview(value),
                start=match.start(1),
                end=match.end(1),
                confidence=0.76,
                severity="high",
                redaction_token=_stable_token("HIGH_ENTROPY_SECRET", value),
            )
        )
    return findings


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * log2(count / length) for count in counts.values())


def _dedupe_overlaps(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    for finding in findings:
        overlaps = [
            existing
            for existing in deduped
            if max(existing.start, finding.start) < min(existing.end, finding.end)
        ]
        if not overlaps:
            deduped.append(finding)
            continue
        strongest = max(overlaps + [finding], key=lambda item: (_severity_rank(item.severity), item.confidence))
        for overlap in overlaps:
            if overlap in deduped:
                deduped.remove(overlap)
        if strongest not in deduped:
            deduped.append(strongest)
    return sorted(deduped, key=lambda item: item.start)
