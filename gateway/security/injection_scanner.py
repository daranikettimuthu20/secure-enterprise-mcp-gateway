"""
Prompt injection detection for tool call arguments.

Two layers:
  1. Heuristic/pattern layer - fast, deterministic, catches known jailbreak
     phrasing, encoding tricks, and instructions smuggled into data fields.
  2. Optional ML layer - a pluggable hook for a lightweight local classifier
     (e.g. protectai/deberta-v3-base-prompt-injection via transformers).
     Disabled by default so the project runs with zero heavy dependencies;
     flip ENABLE_ML_SCANNER=1 once the model is downloaded.

The two layers are combined: heuristics short-circuit on high-confidence
matches (cheap), the ML layer (if enabled) catches paraphrased / subtler
attempts the regexes miss.
"""
from __future__ import annotations
import os
import re
import unicodedata
from gateway.models import Finding, ScanVerdict

ENABLE_ML_SCANNER = os.getenv("ENABLE_ML_SCANNER", "0") == "1"

# --- Known jailbreak / injection phrasing ---------------------------------
_INSTRUCTION_OVERRIDE_PATTERNS = [
    r"ignor(?:e|ing)\b(?:\s+\w+){0,4}\s+(instructions?|prompts?|rules?)",
    r"disregard\b(?:\s+\w+){0,4}\s+(instructions?|prompts?|rules?|above)",
    r"you are now (in )?(dan|developer mode|jailbreak)",
    r"forget\b(?:\s+\w+){0,4}\s+(instructions?|rules?|everything)",
    r"system\s+override",
    r"new instructions?:",
    r"system prompt",
    r"reveal (your|the) (system prompt|instructions|prompt)",
    r"act as (if|though) you (have no|are not) (restrictions|rules|filters)",
    r"pretend (you are|to be) (an? )?(unrestricted|unfiltered|jailbroken)",
    r"override (your|the) (safety|security|content) (policy|settings|filters)",
    r"do anything now",
    r"\bsudo\b.*\b(mode|override)\b",
    r"</?(system|assistant|user)>",   # fake chat-turn delimiters smuggled in data
    r"\[\[?system\]?\]",
]
_COMPILED_OVERRIDE = [re.compile(p, re.IGNORECASE) for p in _INSTRUCTION_OVERRIDE_PATTERNS]

# Imperative-verb-in-a-data-field heuristic: a "filename" or "id" argument
# that reads like a full sentence with an imperative verb is suspicious.
_IMPERATIVE_LEADIN = re.compile(
    r"^\s*(please\s+)?(now\s+)?(ignore|disregard|forget|execute|run|call|send|delete|"
    r"reveal|override|act|pretend|bypass|leak|export|grant)\b",
    re.IGNORECASE,
)

_BASE64_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
_ZERO_WIDTH = re.compile(r"[​‌‍﻿]")

_HOMOGLYPH_RANGES = [
    (0x0400, 0x04FF),    # Cyrillic often used to spoof Latin letters
    (0x1D400, 0x1D7FF),  # Mathematical alphanumeric symbols
]


def _has_homoglyphs(text: str) -> bool:
    for ch in text:
        cp = ord(ch)
        for lo, hi in _HOMOGLYPH_RANGES:
            if lo <= cp <= hi:
                return True
    return False


def _heuristic_scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings

    for pattern in _COMPILED_OVERRIDE:
        m = pattern.search(text)
        if m:
            findings.append(Finding(
                category="prompt_injection",
                detail=f"Matched instruction-override pattern: {pattern.pattern!r}",
                confidence=0.95,
                span=(m.start(), m.end()),
            ))

    if _IMPERATIVE_LEADIN.match(text) and len(text.split()) > 4:
        findings.append(Finding(
            category="prompt_injection",
            detail="Data field contains an imperative-sentence lead-in, unusual for a plain argument",
            confidence=0.5,
        ))

    if _ZERO_WIDTH.search(text):
        findings.append(Finding(
            category="prompt_injection",
            detail="Zero-width characters detected (possible filter-evasion smuggling)",
            confidence=0.7,
        ))

    if _has_homoglyphs(text):
        findings.append(Finding(
            category="prompt_injection",
            detail="Homoglyph characters detected (possible spoofing of Latin instructions)",
            confidence=0.4,
        ))

    for m in _BASE64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            import base64
            padded = blob + "=" * (-len(blob) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            if decoded and any(p.search(decoded) for p in _COMPILED_OVERRIDE):
                findings.append(Finding(
                    category="prompt_injection",
                    detail="Base64-encoded payload decodes to an instruction-override pattern",
                    confidence=0.9,
                    span=(m.start(), m.end()),
                ))
        except Exception:
            pass

    return findings


def _ml_scan(text: str) -> list[Finding]:
    """Optional local transformer classifier. Imported lazily so the base
    project has zero heavy ML dependencies unless explicitly enabled."""
    try:
        from transformers import pipeline  # type: ignore
    except ImportError:
        return []

    global _classifier
    if "_classifier" not in globals():
        globals()["_classifier"] = pipeline(
            "text-classification", model="protectai/deberta-v3-base-prompt-injection"
        )
    result = globals()["_classifier"](text[:2000])[0]
    if result["label"].upper() in ("INJECTION", "LABEL_1") and result["score"] >= 0.5:
        return [Finding(
            category="prompt_injection",
            detail=f"ML classifier flagged text as injection (label={result['label']})",
            confidence=float(result["score"]),
        )]
    return []


def scan_text(text: str) -> list[Finding]:
    text = unicodedata.normalize("NFKC", text)
    findings = _heuristic_scan(text)
    if ENABLE_ML_SCANNER:
        findings.extend(_ml_scan(text))
    return findings


def scan_arguments(arguments: dict, block_threshold: float = 0.6) -> ScanVerdict:
    """Scan every string value in a tool-call arguments dict."""
    all_findings: list[Finding] = []

    def _walk(value):
        if isinstance(value, str):
            all_findings.extend(scan_text(value))
        elif isinstance(value, dict):
            for v in value.values():
                _walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _walk(v)

    _walk(arguments)

    max_conf = max((f.confidence for f in all_findings), default=0.0)
    allowed = max_conf < block_threshold
    reason = None
    if not allowed:
        reason = f"Blocked: prompt injection confidence {max_conf:.2f} >= threshold {block_threshold}"

    return ScanVerdict(allowed=allowed, findings=all_findings, reason=reason)
