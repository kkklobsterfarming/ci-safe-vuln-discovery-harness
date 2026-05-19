#!/usr/bin/env python3
"""
CI-safe vulnerability discovery harness.

The pipeline mirrors the major Project Glasswing-style stages while keeping CI
usage defensive and non-exploitative:

  recon -> hunt -> validate -> gapfill -> dedupe -> trace -> feedback -> proof -> report

The proof stage emits safe verification plans/regression-test guidance only. It
never generates exploit payloads, weaponized PoCs, or offensive instructions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DEFAULT_EXCLUDES = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "reports",
    "tmp",
}

SOURCE_PATTERNS = [
    ("http_query", re.compile(r"\b(request\.(?:args|query|GET)|req\.query|URLSearchParams|searchParams|getParameter\()")),
    ("http_body", re.compile(r"\b(request\.(?:form|json|data)|req\.body|await\s+request\.json\(|bodyParser)")),
    ("http_param", re.compile(r"\b(request\.(?:view_args)|req\.params|params\[|pathParameters|getParam\()")),
    ("env", re.compile(r"\b(os\.environ|process\.env|System\.getenv)")),
    ("argv", re.compile(r"\b(sys\.argv|argparse\.|process\.argv|commander\.)")),
    ("file_upload", re.compile(r"\b(files\[|request\.files|multer\(|UploadFile|multipart)")),
]

SECRET_PATTERNS = [
    ("generic_secret_assignment", re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]

CHECKS = [
    {
        "id": "shell-injection-risk",
        "attack_class": "command injection",
        "severity": "high",
        "languages": {".py", ".js", ".ts", ".mjs", ".cjs"},
        "pattern": re.compile(r"\b(os\.system|subprocess\.(?:Popen|run|call|check_output)|child_process\.(?:exec|execSync)|exec\s*\()"),
        "summary": "Shell execution sink requires review for untrusted input and shell=True/string command use.",
        "validate": "Confirm whether user-controlled data reaches this sink; prefer argv arrays and allowlists.",
        "sink_kind": "shell_execution",
    },
    {
        "id": "sql-concat-risk",
        "attack_class": "SQL injection",
        "severity": "high",
        "languages": {".py", ".js", ".ts", ".php", ".rb", ".go"},
        "pattern": re.compile(r"(?i)(select|insert|update|delete)\s+[^\n;]*(\+|\$\{|%\s*\(|\.format\()"),
        "summary": "SQL statement appears dynamically constructed; verify parameterization.",
        "validate": "Confirm all variables are bound parameters, not interpolated SQL fragments.",
        "sink_kind": "sql_execution",
    },
    {
        "id": "path-traversal-risk",
        "attack_class": "path traversal",
        "severity": "medium",
        "languages": {".py", ".js", ".ts", ".go", ".java"},
        "pattern": re.compile(r"(\b(?:readFile|writeFile|sendFile)\s*\(|\b(?:filepath\.Join|os\.path\.join|open|Path)\s*\()"),
        "summary": "Filesystem access sink; validate path canonicalization and base-directory enforcement.",
        "validate": "Confirm attacker-controlled paths cannot escape intended roots via ../, symlinks, or absolute paths.",
        "sink_kind": "filesystem_access",
    },
    {
        "id": "insecure-deserialization-risk",
        "attack_class": "unsafe deserialization",
        "severity": "high",
        "languages": {".py", ".js", ".ts", ".java", ".rb", ".php"},
        "pattern": re.compile(r"\b(pickle\.loads?|yaml\.load\(|marshal\.loads?|ObjectInputStream|unserialize\(|eval\()"),
        "summary": "Unsafe parser/deserializer sink; verify inputs are trusted or use safe alternatives.",
        "validate": "Confirm untrusted data cannot reach this API; replace with safe_load/JSON/signed formats where possible.",
        "sink_kind": "deserialization",
    },
    {
        "id": "ssrf-risk",
        "attack_class": "SSRF",
        "severity": "medium",
        "languages": {".py", ".js", ".ts", ".go", ".java", ".rb"},
        "pattern": re.compile(r"\b(requests\.(?:get|post|put)|fetch\(|axios\.|http\.Get|http\.Post|new URL\()"),
        "summary": "Outbound request sink; validate URL allowlists and metadata/private-network blocking.",
        "validate": "Confirm user-controlled URLs are restricted by scheme, host allowlist, DNS rebinding protections, and IP range checks.",
        "sink_kind": "outbound_request",
    },
]

SECURITY_BOUNDARY_HINTS = [
    ("authentication", re.compile(r"(?i)\b(auth|login|session|jwt|cookie|oauth|permission|role)\b")),
    ("network", re.compile(r"(?i)\b(fetch|request|axios|http|webhook|callback|url)\b")),
    ("filesystem", re.compile(r"(?i)\b(file|path|upload|download|archive|zip|read|write)\b")),
    ("process", re.compile(r"(?i)\b(exec|spawn|subprocess|shell|command|process)\b")),
    ("secrets", re.compile(r"(?i)\b(secret|token|api[_-]?key|password|credential)\b")),
]

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    id: str
    check_id: str
    attack_class: str
    severity: str
    file: str
    line: int
    evidence: str
    summary: str
    validation_guidance: str
    confidence: str = "needs_review"
    status: str = "candidate"
    sink_kind: str = "unknown"
    root_cause_key: str = ""
    reachable: str = "unknown"
    trace_ids: list[str] = field(default_factory=list)
    proof_plan_id: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class SourceCandidate:
    id: str
    kind: str
    file: str
    line: int
    evidence: str


@dataclass
class GapfillTask:
    id: str
    reason: str
    target: str
    suggested_checks: list[str]
    priority: str
    source_stage: str = "gapfill"


@dataclass
class TraceRecord:
    id: str
    finding_id: str
    status: str
    rationale: str
    source: dict[str, Any] | None = None
    sink: dict[str, Any] | None = None
    distance_lines: int | None = None


@dataclass
class FeedbackTask:
    id: str
    source: str
    finding_id: str | None
    priority: str
    task: str
    rationale: str


@dataclass
class ProofPlan:
    id: str
    finding_id: str
    mode: str
    objective: str
    safe_steps: list[str]
    prohibited: list[str]
    regression_test_hint: str
    defensive_test_template: str
    reviewer_prompt: str


def redact_secret_evidence(text: str) -> str:
    text = re.sub(r"(?i)(\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"])[^'\"]+(['\"])", r"\1<redacted>\2", text)
    text = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA<redacted>", text)
    text = re.sub(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "-----BEGIN <redacted> PRIVATE KEY-----", text)
    return text


def evidence_for(attack_class: str, text: str) -> str:
    clipped = text.strip()[:240]
    if attack_class == "secret exposure":
        return redact_secret_evidence(clipped)
    return clipped


def fingerprint(*parts: object) -> str:
    h = hashlib.sha256("\x00".join(map(str, parts)).encode()).hexdigest()
    return h[:16]


def iter_files(root: Path, excludes: set[str]) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in excludes for part in rel_parts):
            continue
        if any(pattern and any(fnmatch_part(part, pattern) for part in rel_parts) for pattern in excludes if any(ch in pattern for ch in "*?[]")):
            continue
        try:
            if path.stat().st_size > 1_500_000:
                continue
        except OSError:
            continue
        yield path


def fnmatch_part(value: str, pattern: str) -> bool:
    return re.fullmatch(pattern.replace("*", ".*"), value) is not None


def safe_read(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


def load_lines_by_file(root: Path, files: list[Path]) -> dict[str, list[str]]:
    return {str(path.relative_to(root)): safe_read(path) for path in files}


def recon(root: Path, files: list[Path], lines_by_file: dict[str, list[str]]) -> dict[str, Any]:
    exts: dict[str, int] = {}
    manifests = []
    boundaries: dict[str, list[str]] = {name: [] for name, _ in SECURITY_BOUNDARY_HINTS}
    for f in files:
        rel = str(f.relative_to(root))
        exts[f.suffix or "<none>"] = exts.get(f.suffix or "<none>", 0) + 1
        if f.name in {"package.json", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "requirements.txt"}:
            manifests.append(rel)
        haystack = rel + "\n" + "\n".join(lines_by_file.get(rel, [])[:80])
        for name, pat in SECURITY_BOUNDARY_HINTS:
            if pat.search(haystack):
                boundaries[name].append(rel)
    return {
        "root": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(files),
        "extensions": dict(sorted(exts.items(), key=lambda kv: (-kv[1], kv[0]))[:30]),
        "manifests": sorted(manifests),
        "security_boundary_hints": {k: sorted(v)[:30] for k, v in boundaries.items() if v},
        "stages": ["recon", "hunt", "validate", "gapfill", "dedupe", "trace", "feedback", "proof", "report"],
        "ci_safe_scope": "static review only; no exploit generation, weaponized PoCs, or offensive payloads",
    }


def discover_sources(lines_by_file: dict[str, list[str]]) -> list[SourceCandidate]:
    sources: list[SourceCandidate] = []
    for rel, lines in lines_by_file.items():
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue
            for kind, pat in SOURCE_PATTERNS:
                if pat.search(line):
                    sources.append(SourceCandidate(
                        id=fingerprint("source", kind, rel, i, stripped[:120]),
                        kind=kind,
                        file=rel,
                        line=i,
                        evidence=evidence_for("source", stripped),
                    ))
    return sources


def hunt(root: Path, files: list[Path], lines_by_file: dict[str, list[str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path in files:
        rel = str(path.relative_to(root))
        ext = path.suffix
        lines = lines_by_file.get(rel, [])
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue
            for name, pat in SECRET_PATTERNS:
                if pat.search(line):
                    fid = fingerprint("secret", rel, i, stripped[:120])
                    findings.append(Finding(
                        id=fid,
                        check_id=name,
                        attack_class="secret exposure",
                        severity="critical",
                        file=rel,
                        line=i,
                        evidence=evidence_for("secret exposure", stripped),
                        summary="Possible hardcoded credential or private key material.",
                        validation_guidance="If real, revoke/rotate immediately and move to CI secrets or a vault.",
                        sink_kind="secret_material",
                        tags=["recon", "hunt"],
                    ))
            for check in CHECKS:
                if ext not in check["languages"]:
                    continue
                if check["pattern"].search(line):
                    fid = fingerprint(check["id"], rel, i, stripped[:120])
                    findings.append(Finding(
                        id=fid,
                        check_id=check["id"],
                        attack_class=check["attack_class"],
                        severity=check["severity"],
                        file=rel,
                        line=i,
                        evidence=evidence_for(check["attack_class"], stripped),
                        summary=check["summary"],
                        validation_guidance=check["validate"],
                        sink_kind=check["sink_kind"],
                        tags=["hunt"],
                    ))
    return findings


def validate(findings: list[Finding], lines_by_file: dict[str, list[str]]) -> list[Finding]:
    """Independent validation-style heuristics to reduce obvious noise."""
    test_file_markers = ("test", "spec", "mock", "fixture", "example", "demo")
    for f in findings:
        path_lower = f.file.lower()
        evidence_lower = f.evidence.lower()
        surrounding = "\n".join(lines_by_file.get(f.file, [])[max(0, f.line - 4): f.line + 3]).lower()
        if any(marker in path_lower for marker in test_file_markers):
            f.confidence = "low"
            f.status = "suppressed_test_or_fixture"
        elif f.attack_class == "secret exposure":
            f.confidence = "medium"
            f.status = "validated_candidate"
        elif f.attack_class == "command injection" and ("shell=true" in surrounding or re.search(r"exec(?:sync)?\s*\(", surrounding)):
            f.confidence = "medium"
            f.status = "validated_candidate"
        elif f.attack_class == "unsafe deserialization":
            f.confidence = "medium"
            f.status = "validated_candidate"
        elif any(safe_marker in surrounding for safe_marker in ("shell=false", "subprocess.run(cmd", "capture_output=true", "check=false")):
            f.confidence = "low"
            f.status = "candidate_low_confidence"
        else:
            f.confidence = "needs_review"
            f.status = "candidate"
        f.tags.append("validate")
    return findings


def gapfill(recon_doc: dict[str, Any], findings: list[Finding], sources: list[SourceCandidate]) -> list[GapfillTask]:
    tasks: list[GapfillTask] = []
    covered_classes = {f.attack_class for f in findings}
    desired = {
        "command injection": ["shell-injection-risk"],
        "SQL injection": ["sql-concat-risk"],
        "path traversal": ["path-traversal-risk"],
        "unsafe deserialization": ["insecure-deserialization-risk"],
        "SSRF": ["ssrf-risk"],
        "secret exposure": ["generic_secret_assignment", "aws_access_key", "private_key"],
    }
    boundary_hints = recon_doc.get("security_boundary_hints", {})
    for attack_class, checks in desired.items():
        if attack_class not in covered_classes:
            tasks.append(GapfillTask(
                id=fingerprint("gapfill", attack_class, recon_doc.get("root")),
                reason=f"No {attack_class} candidates found; schedule a focused second pass to avoid blind spots.",
                target=attack_class,
                suggested_checks=checks,
                priority="medium" if boundary_hints else "low",
            ))
    for boundary, files in boundary_hints.items():
        related = [f for f in findings if f.file in files]
        if files and not related:
            tasks.append(GapfillTask(
                id=fingerprint("gapfill-boundary", boundary, ",".join(files[:5])),
                reason=f"Security boundary '{boundary}' was detected but produced no findings; requeue focused review.",
                target=boundary,
                suggested_checks=["source discovery", "sink discovery", "reachability trace"],
                priority="medium",
            ))
    if sources and not findings:
        tasks.append(GapfillTask(
            id=fingerprint("gapfill-sources-no-sinks", len(sources)),
            reason="Attacker/input-like sources were detected but no sinks were found; run sink-focused review.",
            target="source-to-sink coverage",
            suggested_checks=[c["id"] for c in CHECKS],
            priority="medium",
        ))
    return tasks


def root_cause_key(f: Finding) -> str:
    normalized = re.sub(r"['\"].*?['\"]", "<str>", f.evidence)
    normalized = re.sub(r"\d+", "<n>", normalized)
    return fingerprint(f.check_id, f.file, normalized[:180])


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        f.root_cause_key = root_cause_key(f)
        if f.root_cause_key not in seen:
            seen[f.root_cause_key] = f
        else:
            existing = seen[f.root_cause_key]
            if SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                seen[f.root_cause_key] = f
    out = list(seen.values())
    for f in out:
        f.tags.append("dedupe")
    return out


def trace(findings: list[Finding], sources: list[SourceCandidate], lines_by_file: dict[str, list[str]]) -> list[TraceRecord]:
    traces: list[TraceRecord] = []
    sources_by_file: dict[str, list[SourceCandidate]] = {}
    for source in sources:
        sources_by_file.setdefault(source.file, []).append(source)

    for f in findings:
        if f.status.startswith("suppressed"):
            f.reachable = "not_applicable"
            continue
        same_file_sources = sources_by_file.get(f.file, [])
        nearest = None
        if same_file_sources:
            nearest = min(same_file_sources, key=lambda s: abs(s.line - f.line))
        if f.attack_class == "secret exposure":
            status = "reachable_not_required"
            rationale = "Secret exposure is actionable without source-to-sink reachability."
        elif nearest and abs(nearest.line - f.line) <= 80:
            status = "possibly_reachable"
            rationale = f"Input-like source '{nearest.kind}' appears within 80 lines of the sink in the same file."
        elif nearest:
            status = "source_same_file_unproven"
            rationale = f"Input-like source '{nearest.kind}' exists in the same file but is not near the sink; manual data-flow review needed."
        else:
            status = "no_source_observed"
            rationale = "No attacker/input-like source was observed in the same file by lightweight tracing."
        trace_id = fingerprint("trace", f.id, status, nearest.id if nearest else "none")
        record = TraceRecord(
            id=trace_id,
            finding_id=f.id,
            status=status,
            rationale=rationale,
            source=asdict(nearest) if nearest else None,
            sink={"file": f.file, "line": f.line, "kind": f.sink_kind, "evidence": f.evidence},
            distance_lines=abs(nearest.line - f.line) if nearest else None,
        )
        f.reachable = status
        f.trace_ids.append(trace_id)
        f.tags.append("trace")
        traces.append(record)
    return traces


def feedback(findings: list[Finding], gapfill_tasks: list[GapfillTask], traces: list[TraceRecord]) -> list[FeedbackTask]:
    tasks: list[FeedbackTask] = []
    trace_by_finding = {t.finding_id: t for t in traces}
    for f in findings:
        if f.status.startswith("suppressed"):
            continue
        tr = trace_by_finding.get(f.id)
        if f.status == "validated_candidate" or (tr and tr.status in {"possibly_reachable", "reachable_not_required"}):
            tasks.append(FeedbackTask(
                id=fingerprint("feedback", f.id, "fix-or-dismiss"),
                source="trace" if tr else "validate",
                finding_id=f.id,
                priority="high" if f.severity in {"critical", "high"} else "medium",
                task="Open a fix-or-dismiss security review item with owner, affected component, and regression-test requirement.",
                rationale=f"{f.severity} {f.attack_class} candidate is {f.status}; reachability={f.reachable}.",
            ))
        elif tr and tr.status == "source_same_file_unproven":
            tasks.append(FeedbackTask(
                id=fingerprint("feedback", f.id, "manual-dataflow"),
                source="trace",
                finding_id=f.id,
                priority="medium",
                task="Run deeper manual/codeql-style data-flow review for this source/sink pair.",
                rationale=tr.rationale,
            ))
    for g in gapfill_tasks:
        tasks.append(FeedbackTask(
            id=fingerprint("feedback", g.id),
            source="gapfill",
            finding_id=None,
            priority=g.priority,
            task=f"Requeue focused coverage task for {g.target}.",
            rationale=g.reason,
        ))
    return tasks


def defensive_template_for(f: Finding) -> str:
    templates = {
        "secret exposure": """# Defensive check template
# Assert committed files do not contain the detected secret pattern.
# If this fails, rotate the value and move it to CI secrets/vault-backed env vars.
def test_no_committed_secret_pattern():
    assert scan_repository_for_secret_patterns() == []
""",
        "command injection": """# Defensive regression template
# Exercise the command wrapper with synthetic metacharacter-like input.
# Expected result: input is treated as inert data or rejected before execution.
def test_command_execution_uses_argv_and_rejects_shell_metacharacters():
    result = call_command_wrapper_with_synthetic_input("SAFE_TEST_INPUT_WITH_METACHARS")
    assert result.was_rejected or result.used_argument_vector_without_shell
""",
        "SQL injection": """# Defensive regression template
# Expected result: untrusted values are bound parameters, never query text.
def test_query_uses_bound_parameters_for_untrusted_values():
    query = build_query_with_synthetic_untrusted_value("SAFE_TEST_VALUE")
    assert query.uses_bound_parameters
    assert "SAFE_TEST_VALUE" not in query.sql_text
""",
        "path traversal": """# Defensive regression template
# Expected result: traversal-like synthetic paths are rejected or normalized inside base dir.
def test_paths_cannot_escape_allowed_base_directory():
    result = resolve_user_path("SYNTHETIC_TRAVERSAL_INPUT")
    assert result.was_rejected or result.resolved_path.is_relative_to(ALLOWED_BASE_DIR)
""",
        "unsafe deserialization": """# Defensive regression template
# Expected result: untrusted serialized input is rejected or handled by a safe parser.
def test_untrusted_serialized_input_uses_safe_parser():
    result = parse_untrusted_serialized_input("SYNTHETIC_UNTRUSTED_INPUT")
    assert result.was_rejected or result.parser_is_safe
""",
        "SSRF": """# Defensive regression template
# Expected result: non-allowlisted and private-network destinations are blocked before fetch.
def test_outbound_url_validation_blocks_untrusted_destinations():
    result = validate_outbound_url("https://example.invalid/synthetic")
    assert result.was_rejected or result.host_is_explicitly_allowlisted
""",
    }
    return templates.get(f.attack_class, "# Add a focused defensive regression test for the expected safe behavior.\n")


def reviewer_prompt_for(f: Finding) -> str:
    return (
        "Review this finding only for defensive validation. "
        "Do not create exploit payloads, bypass instructions, or offensive PoCs. "
        "Determine whether the code path is reachable in authorized test scope, "
        "identify the expected safe behavior, and propose a regression test using synthetic inert inputs. "
        f"Finding: {f.severity} {f.attack_class} at {f.file}:{f.line}. "
        f"Evidence: {f.evidence}"
    )


def proof(findings: list[Finding]) -> list[ProofPlan]:
    plans: list[ProofPlan] = []
    for f in findings:
        if f.status.startswith("suppressed"):
            continue
        if f.status not in {"validated_candidate", "candidate", "candidate_low_confidence"}:
            continue
        objective = f"Safely verify whether {f.attack_class} at {f.file}:{f.line} is real and prevent regressions if fixed."
        generic_steps = [
            "Reproduce only inside an isolated CI/test environment with synthetic inert fixtures.",
            "Confirm the vulnerable code path and expected safe behavior before changing code.",
            "Add a unit or integration regression test that asserts sanitized/rejected handling of malformed input.",
            "Avoid external network targets, real credentials, production data, destructive side effects, exploit chains, and bypass techniques.",
        ]
        hints = {
            "secret exposure": "Assert no committed files match the secret pattern and move required values to CI secrets/vault-backed environment variables.",
            "command injection": "Test that command execution uses argv arrays/allowlists and rejects metacharacters as data, without invoking a shell.",
            "SQL injection": "Test that untrusted values are passed as bound parameters and cannot alter query structure.",
            "path traversal": "Test that traversal-like synthetic paths stay within the allowed base directory or are rejected.",
            "unsafe deserialization": "Test that untrusted serialized input is rejected or parsed by safe loaders only.",
            "SSRF": "Test that non-allowlisted hosts, private IP ranges, metadata IPs, and scheme changes are rejected before outbound fetch.",
        }
        plan = ProofPlan(
            id=fingerprint("proof", f.id),
            finding_id=f.id,
            mode="safe_defensive_reproduction_and_regression_plan",
            objective=objective,
            safe_steps=generic_steps,
            prohibited=[
                "Do not generate exploit payloads or weaponized proof-of-concept code.",
                "Do not target third-party or production systems.",
                "Do not print, persist, or upload real secrets in CI artifacts.",
                "Do not reframe prompts to bypass model or tool safety refusals.",
            ],
            regression_test_hint=hints.get(f.attack_class, "Add a focused regression test for the expected safe behavior."),
            defensive_test_template=defensive_template_for(f),
            reviewer_prompt=reviewer_prompt_for(f),
        )
        f.proof_plan_id = plan.id
        f.tags.append("proof")
        plans.append(plan)
    return plans


def maybe_run_semgrep(root: Path, out_dir: Path) -> dict[str, Any] | None:
    if not os.environ.get("VULN_HARNESS_RUN_SEMGREP"):
        return None
    try:
        result = subprocess.run(
            ["semgrep", "--config", "p/security-audit", "--json", "--output", str(out_dir / "semgrep.json"), str(root)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"enabled": True, "ok": False, "error": str(exc)}
    return {"enabled": True, "ok": result.returncode in (0, 1), "returncode": result.returncode, "stderr_tail": result.stderr[-2000:]}


def build_summary(findings: list[Finding], gapfill_tasks: list[GapfillTask], traces: list[TraceRecord], feedback_tasks: list[FeedbackTask], proof_plans: list[ProofPlan]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "candidate_count": len(findings),
        "validated_candidate_count": sum(1 for f in findings if f.status == "validated_candidate"),
        "suppressed_count": sum(1 for f in findings if f.status.startswith("suppressed")),
        "gapfill_task_count": len(gapfill_tasks),
        "trace_count": len(traces),
        "possibly_reachable_count": sum(1 for t in traces if t.status in {"possibly_reachable", "reachable_not_required"}),
        "feedback_task_count": len(feedback_tasks),
        "proof_plan_count": len(proof_plans),
        "by_severity": {},
        "by_attack_class": {},
        "by_trace_status": {},
    }
    for f in findings:
        summary["by_severity"][f.severity] = summary["by_severity"].get(f.severity, 0) + 1
        summary["by_attack_class"][f.attack_class] = summary["by_attack_class"].get(f.attack_class, 0) + 1
    for t in traces:
        summary["by_trace_status"][t.status] = summary["by_trace_status"].get(t.status, 0) + 1
    return summary


def write_json_artifacts(out_dir: Path, report: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in ("sources", "gapfill", "traces", "feedback", "proof_plans", "findings"):
        (out_dir / f"{name}.json").write_text(json.dumps(report[name], indent=2, sort_keys=True), encoding="utf-8")
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# Vulnerability Discovery Harness Report",
        "",
        f"Generated: `{report['recon']['generated_at']}`",
        "",
        "## Scope",
        "",
        "CI-safe static vulnerability discovery. No exploit generation, weaponized PoCs, or offensive payloads.",
        "",
        "## Stages",
        "",
    ]
    for stage in report["recon"].get("stages", []):
        lines.append(f"- {stage}")
    lines.extend([
        "",
        "## Recon",
        "",
        f"- Files scanned: {report['recon']['file_count']}",
        f"- Manifests: {', '.join(report['recon']['manifests']) or 'none detected'}",
        f"- Boundary hints: {', '.join(report['recon'].get('security_boundary_hints', {}).keys()) or 'none detected'}",
        "",
        "## Summary",
        "",
        f"- Candidate findings: {report['summary']['candidate_count']}",
        f"- Validated candidates: {report['summary']['validated_candidate_count']}",
        f"- Suppressed test/fixture findings: {report['summary']['suppressed_count']}",
        f"- Gapfill tasks: {report['summary']['gapfill_task_count']}",
        f"- Trace records: {report['summary']['trace_count']}",
        f"- Possibly reachable / reachability-not-required: {report['summary']['possibly_reachable_count']}",
        f"- Feedback tasks: {report['summary']['feedback_task_count']}",
        f"- Safe proof plans: {report['summary']['proof_plan_count']}",
        "",
        "## Gapfill Tasks",
        "",
    ])
    for task in report["gapfill"][:50]:
        lines.extend([
            f"- `{task['id']}` **{task['priority']}** {task['target']}: {task['reason']}",
        ])
    if not report["gapfill"]:
        lines.append("No gapfill tasks generated.")
    lines.extend(["", "## Findings", ""])
    trace_by_finding: dict[str, list[dict[str, Any]]] = {}
    for tr in report["traces"]:
        trace_by_finding.setdefault(tr["finding_id"], []).append(tr)
    for f in report["findings"][:200]:
        lines.extend([
            f"### {f['severity'].upper()} {f['attack_class']} — `{f['file']}:{f['line']}`",
            "",
            f"- ID: `{f['id']}`",
            f"- Check: `{f['check_id']}`",
            f"- Status: `{f['status']}`",
            f"- Confidence: `{f['confidence']}`",
            f"- Reachability: `{f.get('reachable', 'unknown')}`",
            f"- Proof plan: `{f.get('proof_plan_id') or 'none'}`",
            f"- Summary: {f['summary']}",
            f"- Validation: {f['validation_guidance']}",
        ])
        for tr in trace_by_finding.get(f["id"], []):
            lines.append(f"- Trace `{tr['id']}`: {tr['status']} — {tr['rationale']}")
        lines.extend([
            "- Evidence:",
            "",
            "```text",
            f["evidence"],
            "```",
            "",
        ])
    if not report["findings"]:
        lines.append("No candidate findings detected by the built-in checks.\n")
    lines.extend(["", "## Feedback Tasks", ""])
    for task in report["feedback"][:100]:
        lines.append(f"- `{task['id']}` **{task['priority']}**: {task['task']} ({task['rationale']})")
    if not report["feedback"]:
        lines.append("No feedback tasks generated.")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="CI-safe vulnerability discovery harness")
    parser.add_argument("--root", default=".", help="repository root to scan")
    parser.add_argument("--out", default="reports/vuln-harness", help="output directory")
    parser.add_argument("--fail-on", choices=["none", "critical", "validated", "reachable"], default=os.environ.get("VULN_HARNESS_FAIL_ON", "none"))
    parser.add_argument("--exclude", action="append", default=[], help="additional path component/glob to exclude")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    excludes = set(DEFAULT_EXCLUDES) | set(args.exclude)
    files = list(iter_files(root, excludes))
    lines_by_file = load_lines_by_file(root, files)

    recon_doc = recon(root, files, lines_by_file)
    sources = discover_sources(lines_by_file)
    findings = validate(hunt(root, files, lines_by_file), lines_by_file)
    gapfill_tasks = gapfill(recon_doc, findings, sources)
    findings = dedupe(findings)
    traces = trace(findings, sources, lines_by_file)
    feedback_tasks = feedback(findings, gapfill_tasks, traces)
    proof_plans = proof(findings)
    semgrep = maybe_run_semgrep(root, out_dir)
    summary = build_summary(findings, gapfill_tasks, traces, feedback_tasks, proof_plans)

    report = {
        "schema": "vuln-discovery-harness/v2",
        "recon": recon_doc,
        "summary": summary,
        "semgrep": semgrep,
        "sources": [asdict(s) for s in sources],
        "gapfill": [asdict(t) for t in gapfill_tasks],
        "findings": [asdict(f) for f in findings],
        "traces": [asdict(t) for t in traces],
        "feedback": [asdict(t) for t in feedback_tasks],
        "proof_plans": [asdict(p) for p in proof_plans],
    }
    write_json_artifacts(out_dir, report)
    write_markdown(report, out_dir / "report.md")

    print(json.dumps(summary, indent=2, sort_keys=True))

    if args.fail_on == "critical" and any(f.severity == "critical" and not f.status.startswith("suppressed") for f in findings):
        return 2
    if args.fail_on == "validated" and any(f.status == "validated_candidate" for f in findings):
        return 2
    if args.fail_on == "reachable" and any(t.status in {"possibly_reachable", "reachable_not_required"} for t in traces):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
