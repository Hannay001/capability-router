#!/usr/bin/env python3
"""Static prompt-injection and capability-safety auditor.

Scans skill/plugin/MCP definition files for patterns associated with prompt
injection, secret exfiltration, obfuscated execution, and destructive commands.
Pure standard library, no network access, no model calls.

Verdicts:
    clean    no findings above informational severity
    suspect  at least one high finding or several medium findings
    hostile  any critical finding or multiple high findings

Exit codes with --strict: 0 clean, 1 suspect or partially-skipped targets,
2 hostile, also 2 when nothing at all could be audited.
"""
from __future__ import annotations

import argparse
import json
import re
import unicodedata
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

AUDIT_MAX_BYTES = 8 * 1024 * 1024

AUDITABLE_SUFFIXES = {".md", ".json", ".toml", ".yaml", ".yml", ".mjs", ".js", ".py", ".sh", ".txt"}

# Executable/bytecode payloads are not auditable as text, but shipping them
# inside a capability directory is itself a smuggling signal: they are hashed
# and floored to "suspect" instead of being silently ignored.
BINARY_PAYLOAD_SUFFIXES = {
    ".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll", ".exe", ".wasm", ".o", ".a"
}

# Indicative mapping from cap rules to Tencent SkillTrustBench categories
# (T01 instruction hijacking, T02 memory poisoning, T03 remote payload /
# network egress, T04 embedded malicious code, T05 privilege & access abuse,
# T08 insecure dependencies, T09 insecure practices). Meta-findings carry an
# empty taxonomy.
RULE_TAXONOMY: dict[str, str] = {
    "instruction_override": "T01",
    "hidden_directive_text": "T01/T02",
    "unclosed_comment_directive": "T01/T02",
    "vulnerable_dependency": "T08",
    "invisible_unicode": "T01",
    "homoglyph_mixing": "T01",
    "exfiltration_pipeline": "T03",
    "pipeless_exfiltration": "T03",
    "heredoc_exfiltration": "T03",
    "url_data_beacon": "T03",
    "backtick_substitution_exfil": "T03",
    "non_text_payload": "T03",
    "obfuscated_execution": "T04",
    "non_utf8_content": "T04",
    "oversized_skipped": "T04",
    "credential_access": "T05",
    "token_harvesting_env": "T05",
    "destructive_command": "T05",
}

# (rule_id, severity, compiled regex, human title)
RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "instruction_override",
        "high",
        re.compile(
            r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+instructions?"
            r"|disregard\s+(?:all\s+|any\s+)?(?:previous|prior|your)\s+(?:instructions|rules|guidelines)"
            r"|\bnew\s+system\s+prompt\b"
            r"|\byou\s+are\s+now\s+(?:a|an|the)\b",
            re.IGNORECASE,
        ),
        "Attempts to override agent instructions",
    ),
    (
        "exfiltration_pipeline",
        "critical",
        re.compile(
            r"(?:curl|wget|nc|netcat|Invoke-WebRequest|Invoke-RestMethod|requests\.post|fetch\()"
            r"[^|\n]*\|\s*(?:sh|bash|zsh|python\w*)"
            # cap-audit-suppress (next line documents the exfiltration shape)
            r"|(?:cat|print|echo|type)\s[^|\n]*(?:\.env|id_rsa|credentials|\.aws|keychain)[^|\n]*\|"
            r"[^|\n]*(?:curl|wget|nc|http)",
            re.IGNORECASE,
        ),
        "Pipes files or secrets into a network command",
    ),
    (
        "credential_access",
        "high",
        re.compile(
            r"~/?\.(?:ssh|aws|gnupg|config/gcloud)\b"
            r"|\bid_rsa\b|\bed25519\b|\.ssh/authorized_keys"  # cap-audit-suppress
            r"|security\s+(?:find-generic-password|find-internet-password)"
            r"|secret-tool\s+lookup"
            r"|(?:read|cat|open|Get-Content)[^\n]{0,40}\.env\b",  # cap-audit-suppress
            re.IGNORECASE,
        ),
        "Reads credential stores or secret files",
    ),
    (
        "token_harvesting_env",
        "high",
        re.compile(
            r"(?:api[_-]?key|auth[_-]?token|access[_-]?token|secret|password)"
            r"[^=\n]{0,20}[=:][^\n]{0,10}(?:process\.env|os\.environ|ENV\[)",
            re.IGNORECASE,
        ),
        "Harvests token-like environment variables",
    ),
    (
        "obfuscated_execution",
        "high",
        re.compile(
            r"base64\s+(?:-d|-D|--decode)[^|\n]*\|\s*(?:sh|bash|zsh|powershell)"
            r"|\beval\s*\(\s*(?:atob|Buffer|compile)"
            r"|\bexec\s*\(\s*(?:request|urlopen|fetch)"
            r"|execSync\([^\n]*(?:curl|wget|https?://)"
            r"|eval\s*\([^\n]*(?:__import__|require\()"
            r"|FromBase64String\s*\(",
            re.IGNORECASE,
        ),
        "Decodes and executes obfuscated payloads",
    ),
    (
        "destructive_command",
        "high",
        re.compile(
            r"\brm\s+(?:-{1,2}[A-Za-z-]+\s+)*-(?:[A-Za-z]*r[A-Za-z]*f|[A-Za-z]*f[A-Za-z]*r)[A-Za-z]*\s+"
            r"(?:/|~/|~(?:\s|$)|\$HOME|/(?:etc|home|usr|var|bin|sbin|lib|opt)\b)[^\n]*"
            r"|\brm\s+[^\n]{0,60}(?:/|~/|\$HOME)[^\n]*--no-preserve-root"
            r"|git\s+push\s+(?:--force|-f)[^\n]*\b(?:main|master)\b"
            r"|chmod\s+-R\s+777\s+/"
            r"|\bdd\s+if=[^\n]+\bof=/dev/"
            r"|\bmkfs\b",
            re.IGNORECASE,
        ),
        "Destroys data or forces protected history rewrites",
    ),
    (
        "pipeless_exfiltration",
        "critical",
        re.compile(
            # cap-audit-suppress
            r"(?:curl|wget)[^\n]*(?:--data(?:-binary|-raw|-urlencode)?|\s-d\s|--upload-file|\s-T\s)\s*[^\n]*@"
            # cap-audit-suppress
            r"|wget[^\n]*--post-file=[^\n]*@"  # cap-audit-suppress
            # cap-audit-suppress
            r"|curl[^\n]*--json\s*@"
            r"|/dev/tcp/[\w.-]+/\d+"
            r"|(?:python3?|node|ruby|perl)\s+(?:-c|-e)\s+[\"'][^\n]*(?:urllib|requests|httpx|http\.client|https?://)"
            r"|(?:dig|nslookup|host)\s[^\n]*\$\(",
            re.IGNORECASE,
        ),
        "Exfiltrates files or calls the network without a visible pipe",
    ),
    (
        "heredoc_exfiltration",
        "high",
        re.compile(
            r"(?:python3?|node|ruby|perl)[^\n]*-\s*<<"
            r"|<<[-']?(?:PY|EOF|JS|RB|SCRIPT)\b"
        ),
        "Interpreter heredoc body (network tokens inside are scanned by span rules)",
    ),
    (
        "url_data_beacon",
        "medium",
        re.compile(r"!\[[^\]]*\]\(https?://[^)]*\?"),
        "Outbound beacon URL capable of carrying encoded data",
    ),

    (
        "backtick_substitution_exfil",
        "critical",
        re.compile(r"(?:dig|nslookup|host)\s[^\n]*`[^`]+`"),
        "Command substitution piped into DNS resolution",
    ),
    (
        "hidden_directive_text",
        "medium",
        re.compile(
            r"<!--[\s\S]{0,400}?(?:always|must|never|important:|note to (?:the )?(?:model|agent)|assistant:)"
            r"[\s\S]{0,200}?-->"
        ),
        "Hides directives inside comments or invisible markup",
    ),
]

UNCLOSED_COMMENT_SPAN = re.compile(r"<!--(?![\s\S]*-->)[\s\S]{0,400}?(?:always|must|never|important:)", re.IGNORECASE)

_HIDDEN_DIRECTIVE_SPAN_PATTERN = (
    r"<!--[\s\S]{0,600}?(?:always|must|never|important:|note to (?:the )?(?:model|agent)|assistant:)[\s\S]{0,300}?-->"
)
HIDDEN_DIRECTIVE_SPAN = re.compile(_HIDDEN_DIRECTIVE_SPAN_PATTERN)

# Invisible characters that should never appear in trusted instruction files.
_INVISIBLE_CODEPOINTS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # byte-order mark used mid-file
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\u202a",  # LRE embedding
    "\u202b",  # RLE embedding
    "\u202c",  # PDF directional override terminator
    "\u202d",  # LRO override
    "\u202e",  # RLO override (classic spoofing trick)
    "\u2066",  # LRI isolate
    "\u2067",  # RLI isolate
    "\u2068",  # FSI first-strong isolate
    "\u2069",  # PDI isolate terminator
    "\ufe00", "\ufe01", "\ufe02", "\ufe03", "\ufe04", "\ufe05",
    "\ufe06", "\ufe07", "\ufe08", "\ufe09", "\ufe0a", "\ufe0b",
    "\ufe0c", "\ufe0d", "\ufe0e", "\ufe0f",
    "\U000e0100", "\U000e0101", "\U000e0102",
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    line: int
    excerpt: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "line": self.line,
            "excerpt": self.excerpt,
            "taxonomy": RULE_TAXONOMY.get(self.rule_id, ""),
        }


@dataclass
class FileReport:
    path: str
    sha256: str
    verdict: str
    findings: list[Finding] = field(default_factory=list)


_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-_][0-?]*[ -/]*[@-~]|[\x80-\x9f])")
_C0_C1_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_CREDENTIAL_RE = re.compile(
    r"(?i)(bearer\s+)[\w.=-]{8,}"
    r"|(sk-(?:proj|ant)-?[A-Za-z0-9_-]{16,})"
    r"|(sk-[A-Za-z0-9]{16,})"
    r"|(gh[pousr]_[A-Za-z0-9]{20,})"
    r"|(github_pat_[A-Za-z0-9_]{20,})"
    r"|(xox[baprs]-[A-Za-z0-9-]{10,})"
    r"|(sk_live_[A-Za-z0-9]{16,})"
    r"|(AIza[A-Za-z0-9_-]{30,})"
    r"|(npm_[A-Za-z0-9]{30,})"
    r"|(AKIA[0-9A-Z]{16})"
    r"|((?i:[A-Za-z0-9/+=]{40}))"
)


def _sanitize_excerpt(snippet: str) -> str:
    snippet = _ANSI_ESCAPE_RE.sub("", _C0_C1_RE.sub("", snippet))
    return _CREDENTIAL_RE.sub(lambda m: next(g for g in m.groups() if g) + "[REDACTED]", snippet)


def _excerpt(line: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 30)
    end = min(len(line), match.end() + 30)
    snippet = line[start:end].strip()
    return _sanitize_excerpt(re.sub(r"\s+", " ", snippet))[:160]


def _invisible_findings(lines: list[str], findings: list[Finding]) -> None:
    for number, line in enumerate(lines, start=1):
        for char in line:
            if char in _INVISIBLE_CODEPOINTS:
                findings.append(
                    Finding(
                        rule_id="invisible_unicode",
                        severity="medium",
                        title="Invisible Unicode character embedded in text",
                        line=number,
                        excerpt=f"U+{ord(char):04X}",
                    )
                )
                break


def _homoglyph_lines(lines: list[str]) -> int:
    """Count lines mixing ASCII letters with Cyrillic/Greek look-alikes."""
    suspicious_scripts = ("CYRILLIC", "GREEK")
    count = 0
    for line in lines:
        has_ascii = any("a" <= c.lower() <= "z" for c in line)
        has_lookalike = any(
            unicodedata.name(c, "").startswith(suspicious_scripts) for c in line
        )
        if has_ascii and has_lookalike:
            count += 1
    return count


_REPO_ROOT = Path(__file__).resolve().parents[1]


def _suppression_allowed(path: Path) -> bool:
    """Suppression markers are a first-party documentation tool.

    Only files inside cap's own repository may use cap-audit-suppress; for any
    other (potentially hostile) input the marker is inert and every rule fires.
    """
    try:
        path.resolve(strict=False).relative_to(_REPO_ROOT)
        return True
    except ValueError:
        return False


MAX_RULE_LINE_CHARS = 4096
MAX_SPAN_SCAN_CHARS = 65_536


def audit_bytes(path: Path, content: bytes) -> FileReport:
    import hashlib

    sha256 = hashlib.sha256(content).hexdigest()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return FileReport(
            path=str(path),
            sha256=sha256,
            verdict="suspect",
            findings=[
                Finding(
                    rule_id="non_utf8_content",
                    severity="medium",
                    title="File is not valid UTF-8",
                    line=0,
                    excerpt="",
                )
            ],
        )
    # Split on \n ONLY: str.splitlines() also breaks on U+2028/U+2029/U+0085,
    # which editors render inline and which would otherwise hide pipe characters
    # from line-based rules.
    lines = text.split("\n")
    allow_suppression = _suppression_allowed(path)
    suppressed = {
        number
        for number, line in enumerate(lines, start=1)
        if allow_suppression and "cap-audit-suppress" in line
    }
    findings: list[Finding] = []
    if "cap-audit-suppress" in text and not allow_suppression:
        # Marker in an untrusted file is inert, but its presence is surfaced so
        # an auditor knows suppression was attempted.
        findings.append(
            Finding(
                rule_id="suppress_marker_outside_first_party",
                severity="medium",
                title="Suppression marker present but ignored outside cap's own repo",
                line=text[: text.index("cap-audit-suppress")].count("\n") + 1,
                excerpt="cap-audit-suppress",
            )
        )
    if suppressed:
        # Suppression is legitimate for first-party docs that quote attack
        # patterns, but it must never be silent either: first-party usage is
        # surfaced at medium (visible, verdict-visible via three-plus counts)
        # while the same marker in an untrusted file stays high.
        findings.append(
            Finding(
                rule_id="suppress_marker_used",
                severity="medium" if allow_suppression else "high",
                title="cap-audit-suppress marker present (review intent)",
                line=min(suppressed),
                excerpt=f"{len(suppressed)} marker line(s)",
            )
        )
    for rule_id, severity, pattern, title in RULES:
        for number, line in enumerate(lines, start=1):
            if len(line) > MAX_RULE_LINE_CHARS:
                continue  # ReDoS guard: pathological lines are reported separately
            if number in suppressed or (number - 1) in suppressed:
                continue  # marker applies to its own line and the next one
            match = pattern.search(line)
            if match is None:
                continue
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    line=number,
                    excerpt=_excerpt(line, match),
                )
            )
    # Hidden directives often span multiple lines inside one comment; line-based
    # scanning above misses those, so also scan joined text. In first-party files
    # with explicit markers this span scan is skipped alongside the marked lines;
    # for external input it always runs.
    if (not allow_suppression or not suppressed) and UNCLOSED_COMMENT_SPAN.search(
        text[:MAX_SPAN_SCAN_CHARS]
    ):
        findings.append(
            Finding(
                rule_id="unclosed_comment_directive",
                severity="high",
                title="Unclosed HTML comment hiding directives indefinitely",
                line=text[: text.index("<!--")].count("\n") + 1,
                excerpt="unterminated <!-- block",
            )
        )
    if (not allow_suppression or not suppressed) and HIDDEN_DIRECTIVE_SPAN.search(
        text[:MAX_SPAN_SCAN_CHARS]
    ):
        findings.append(
            Finding(
                rule_id="hidden_directive_text",
                severity="medium",
                title="Hides directives inside a multi-line comment",
                line=0,
                excerpt="multi-line comment block",
            )
        )
    _invisible_findings(lines, findings)
    homoglyph_lines = _homoglyph_lines(lines)
    if homoglyph_lines:
        findings.append(
            Finding(
                rule_id="homoglyph_mixing",
                severity="medium",
                title="Mixes Latin letters with Cyrillic/Greek look-alikes",
                line=0,
                excerpt=f"{homoglyph_lines} line(s) affected",
            )
        )
    return FileReport(path=str(path), sha256=sha256, verdict=_verdict(findings), findings=findings)


def _verdict(findings: list[Finding]) -> str:
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    if critical or high >= 2:
        return "hostile"
    if high or medium >= 3:
        return "suspect"
    return "clean"


def audit_path(path: Path) -> Optional[FileReport]:
    resolved = path.expanduser()
    if "__pycache__" in resolved.parts:
        return None  # interpreter bytecode cache, not shipped capability content
    if resolved.is_symlink():
        # A symlinked file can point anywhere (e.g. ~/.ssh/id_rsa); auditing it  # cap-audit-suppress
        # would hash and excerpt out-of-scope content.
        return None
    if not resolved.is_file():
        return None
    suffix = resolved.suffix.lower()
    if suffix in BINARY_PAYLOAD_SUFFIXES:
        import hashlib

        try:
            with resolved.open("rb") as handle:
                blob = handle.read(AUDIT_MAX_BYTES)
        except OSError:
            return None
        oversized_blob = resolved.stat().st_size > AUDIT_MAX_BYTES
        findings = [
            Finding(
                rule_id="non_text_payload",
                severity="high",
                title=(
                    f"Executable payload ({suffix}) shipped inside capability directory"
                    + "; oversize, hash covers prefix only"
                    if oversized_blob
                    else f"Executable payload ({suffix}) shipped inside capability directory"
                ),
                line=0,
                excerpt=f"sha256={hashlib.sha256(blob).hexdigest()[:16]}",
            )
        ]
        digest = hashlib.sha256(blob).hexdigest()
        return FileReport(path=str(resolved), sha256=digest, verdict=_verdict(findings), findings=findings)
    if suffix not in AUDITABLE_SUFFIXES:
        return None
    try:
        if resolved.stat().st_size > AUDIT_MAX_BYTES:
            # Scan the readable prefix so attacks hiding before the cap are
            # still caught, mark the unscanned tail loudly, and never let an
            # unscanned file pass a strict gate as "clean".
            with resolved.open("rb") as size_handle:
                prefix = size_handle.read(AUDIT_MAX_BYTES)
            report = audit_bytes(resolved, prefix)
            report.findings.append(
                Finding(
                    rule_id="oversized_skipped",
                    severity="high",
                    title=(
                        f"File exceeds {AUDIT_MAX_BYTES // (1024 * 1024)} MB; "
                        "tail not scanned (hash covers scanned prefix only)"
                    ),
                )
            )
            if report.verdict == "clean":
                report.verdict = "suspect"
            return report
        content = resolved.read_bytes()
    except OSError:
        return None
    return audit_bytes(resolved, content)


def audit_targets(
    targets: Iterable[Path], *, recursive: bool = False
) -> tuple[list[FileReport], list[str]]:
    reports: list[FileReport] = []
    skipped: list[str] = []
    for target in targets:
        target = target.expanduser()
        if not target.exists():
            skipped.append(str(target))
            continue
        if target.is_dir():
            for candidate in sorted(target.rglob("*") if recursive else target.glob("*")):
                report = audit_path(candidate)
                if report is not None:
                    reports.append(report)
        else:
            report = audit_path(target)
            if report is not None:
                reports.append(report)
            else:
                skipped.append(str(target))
    return reports, skipped


# --- Optional dependency CVE gate (opt-in via --check-deps; network used
# only for the keyless osv.dev batch API, failures degrade to info). ---

_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(?P<ver>[A-Za-z0-9][A-Za-z0-9._!*+~-]*)"
)
_NPM_VERSION_RE = re.compile(r"\"(?P<name>@?[A-Za-z0-9][A-Za-z0-9._/-]*)\"\s*:\s*\"(?P<ver>\d[0-9A-Za-z.+~^-]*)\"")


def parse_dependency_manifests(text: str, filename: str) -> list[tuple[str, str, str]]:
    """Extract (ecosystem, name, version) triples from requirements.txt / package.json."""
    deps: list[tuple[str, str, str]] = []
    if filename == "requirements.txt":
        for raw in text.split("\n"):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue  # comments and -r/--hash directives
            match = _REQUIREMENT_RE.match(line)
            if match:
                deps.append(("PyPI", match.group("name"), match.group("ver").rstrip(".*")))
    elif filename == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return deps
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies"):
                entries = data.get(section)
                if not isinstance(entries, dict):
                    continue
                for name, spec in entries.items():
                    match = _NPM_VERSION_RE.search(f'"{name}": "{spec}"')
                    if match:
                        deps.append(("npm", name, match.group("ver")))
    return deps


def query_osv_batch(deps: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
    """Query osv.dev for known vulns; returns map dep -> [GHSA/CVE ids].

    Raises OSError/urllib errors on network failure -- callers degrade.
    """
    if not deps:
        return {}
    payload = json.dumps(
        {"queries": [{"package": {"ecosystem": eco, "name": name}, "version": ver} for eco, name, ver in deps]}
    ).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - fixed https endpoint, no user input in URL
        "https://api.osv.dev/v1/querybatch",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
        results = json.loads(response.read().decode("utf-8")).get("results", [])
    found: dict[tuple[str, str, str], list[str]] = {}
    for dep, result in zip(deps, results, strict=False):
        vulns = result.get("vulns") if isinstance(result, dict) else None
        if vulns:
            found[dep] = sorted({str(v.get("id", "?")) for v in vulns})[:5]
    return found


def dependency_findings(target: Path) -> tuple[list[Finding], list[str]]:
    """Scan a directory tree for pinned dependency manifests and check them."""
    resolved = target.expanduser()
    if not resolved.is_dir():
        return [], []
    manifests: dict[str, list[tuple[str, str, str]]] = {}
    manifest_paths: dict[str, Path] = {}
    for candidate in sorted(resolved.rglob("*")):
        if "__pycache__" in candidate.parts or candidate.name not in ("requirements.txt", "package.json"):
            continue
        if not candidate.is_file() or candidate.is_symlink():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")[:262_144]
        except OSError:
            continue
        key = f"{candidate}:{candidate.name}"
        deps = parse_dependency_manifests(text, candidate.name)
        if deps:
            manifests[key] = deps
            manifest_paths[key] = candidate

    findings: list[Finding] = []
    checked: list[str] = []
    flat: list[tuple[str, str, str]] = []
    owner: dict[tuple[str, str, str], str] = {}
    for key, deps in manifests.items():
        checked.append(key)
        for dep in deps:
            if dep not in owner:
                flat.append(dep)
                owner[dep] = key
    if not flat:
        return [], checked
    try:
        vuln_map = query_osv_batch(flat)
    except Exception as error:  # network unavailable: degrade loudly but cleanly
        findings.append(
            Finding(
                rule_id="dep_check_unavailable",
                severity="info",
                title=f"Dependency CVE check skipped ({type(error).__name__})",
                line=0,
                excerpt=str(error)[:120],
            )
        )
        return findings, checked
    for dep, vuln_ids in vuln_map.items():
        origin = manifest_paths.get(owner[dep])
        findings.append(
            Finding(
                rule_id="vulnerable_dependency",
                severity="high",
                title=f"{dep[1]} {dep[2]} has known vulnerabilities ({dep[0]})",
                line=0,
                excerpt=f"{' '.join(vuln_ids)}  ({origin})" if origin else " ".join(vuln_ids),
            )
        )
    return findings, checked


def run_audit_flow(
    targets: Iterable[Path], *, recursive: bool = False, check_deps: bool = False
) -> tuple[list[FileReport], list[str]]:
    """Shared audit pipeline for the CLI and standalone dispatch."""
    reports, skipped = audit_targets(targets, recursive=recursive)
    if check_deps:
        for target in targets:
            dep_findings, _checked = dependency_findings(target)
            if dep_findings:
                reports.append(
                    FileReport(
                        path=f"<deps:{target}>",
                        sha256="-",
                        verdict=_verdict(dep_findings),
                        findings=dep_findings,
                    )
                )
    return reports, skipped


def overall_verdict(reports: list[FileReport]) -> str:
    worst = "clean"
    for report in reports:
        if SEVERITY_ORDER_VERDICT[report.verdict] > SEVERITY_ORDER_VERDICT[worst]:
            worst = report.verdict
    return worst


SEVERITY_ORDER_VERDICT = {"clean": 0, "suspect": 1, "hostile": 2}

STRICT_EXIT_CODES = {"clean": 0, "suspect": 1, "hostile": 2}


def emit(reports: list[FileReport], as_json: bool, skipped: Optional[list[str]] = None) -> None:
    verdict = overall_verdict(reports)
    skipped = skipped or []
    if as_json:
        print(
            json.dumps(
                {
                    "verdict": verdict,
                    "skipped": skipped,
                    "files": [
                        {
                            "path": report.path,
                            "sha256": report.sha256,
                            "verdict": report.verdict,
                            "findings": [finding.to_dict() for finding in report.findings],
                        }
                        for report in reports
                    ],
                },
                indent=2,
                ensure_ascii=True,
            )
        )
        return
    print(f"verdict: {verdict}")
    for path in skipped:
        print(f"skipped (missing or not auditable): {path}")
    for report in reports:
        if report.verdict == "clean" and not report.findings:
            continue
        print(f"\n{report.path} [{report.verdict}] sha256={report.sha256[:12]}")
        for finding in report.findings:
            location = f":{finding.line}" if finding.line else ""
            print(f"  [{finding.severity}] {finding.rule_id}{location}: {finding.title}")
            if finding.excerpt:
                print(f"      {finding.excerpt}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cap-audit",
        description="Static prompt-injection and safety audit for capability files",
    )
    parser.add_argument("targets", nargs="*", type=Path, help="Files or directories to audit")
    parser.add_argument("--recursive", action="store_true", help="Recurse into directories")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 0 clean / 1 suspect or any skipped target / 2 hostile (or nothing audited)",
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Also check pinned requirements.txt/package.json deps against osv.dev (network; degrades offline)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    targets = args.targets or [Path(".")]
    reports, skipped = run_audit_flow(targets, recursive=args.recursive, check_deps=args.check_deps)
    emit(reports, args.json, skipped)
    if args.strict:
        if skipped and not reports:
            return 2  # nothing audited at all: hostile-grade CI failure
        if skipped:
            return 1  # partially skipped: suspect-grade, per README strict contract
        return STRICT_EXIT_CODES[overall_verdict(reports)]
    return 0


def main_hook(argv: Optional[list[str]] = None) -> int:
    """Runtime filter for coding-agent hooks (Claude Code / Codex contract).

    Reads one hook payload from stdin. JSON payloads (PreToolUse shape with
    ``tool_name`` / ``tool_input``) are scanned structurally; anything else is
    scanned verbatim. Exit codes follow the hook convention:
    0 = allow, 2 = block the tool call (reason goes to stderr).
    """
    import sys

    parser = argparse.ArgumentParser(
        prog="cap hook",
        description="Scan a live tool-call payload from stdin; exit 2 blocks the call",
    )
    parser.add_argument("--json", action="store_true", help="Emit the full report as JSON")
    args = parser.parse_args(argv)

    raw = sys.stdin.read()
    tool_name = "<stdin>"
    body = raw
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        tool_name = str(parsed.get("tool_name") or "<stdin>")
        body = f"tool_name: {tool_name}\n" + json.dumps(
            parsed.get("tool_input", parsed), indent=1, ensure_ascii=True
        )

    report = audit_bytes(Path(f"<hook:{tool_name}>"), body.encode("utf-8"))
    if args.json:
        print(
            json.dumps(
                {
                    "verdict": report.verdict,
                    "sha256": report.sha256,
                    "findings": [finding.to_dict() for finding in report.findings],
                },
                indent=2,
                ensure_ascii=True,
            )
        )
    else:
        emit([report], False)
    if report.verdict == "hostile":
        print(f"cap hook: blocked {tool_name} (hostile content)", file=sys.stderr)
        return 2
    if report.verdict == "suspect":
        print("cap hook: suspect content allowed; review recommended", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
