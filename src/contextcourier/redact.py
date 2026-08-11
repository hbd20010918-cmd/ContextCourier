"""High-confidence secret detection and value-only redaction.

The detector is intentionally conservative: known credential containers are excluded by
path before this module runs, and this module removes common token shapes from allowed
text files. It is a safety layer, not a proof that arbitrary input contains no secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable, Match, Pattern


MARKER_PREFIX = "<<CONTEXTCOURIER_REDACTED:"


@dataclass(frozen=True)
class RedactionResult:
    text: str
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


Replacement = str | Callable[[Match[str]], str | None]


@dataclass(frozen=True)
class Detector:
    kind: str
    pattern: Pattern[str]
    replacement: Replacement | None = None

    def apply(self, text: str) -> tuple[str, int]:
        count = 0
        marker = f"{MARKER_PREFIX}{self.kind}>>"

        def replace(match: Match[str]) -> str:
            nonlocal count
            if callable(self.replacement):
                value = self.replacement(match)
                if value is None or value == match.group(0):
                    return match.group(0)
                count += 1
                return value
            count += 1
            return self.replacement if isinstance(self.replacement, str) else marker

        return self.pattern.sub(replace, text), count


def _marker(kind: str) -> str:
    return f"{MARKER_PREFIX}{kind}>>"


def _url_replacement(match: Match[str]) -> str:
    return f"{match.group('scheme')}{_marker('URL_USERNAME')}:{_marker('URL_PASSWORD')}@"


def _authorization_replacement(match: Match[str]) -> str | None:
    prefix = match.group("prefix") or ""
    scheme = match.group("scheme")
    if _looks_like_placeholder(match.group("value")):
        return None
    return f"{prefix}{scheme} {_marker('AUTHORIZATION')}"


SENSITIVE_KEY = (
    r"(?:[A-Za-z0-9]+[_-])*"
    r"(?:secret[_-]?key[_-]?base|rails[_-]?master[_-]?key|"
    r"api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"secret[_-]?access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"password|passwd|secret|token)"
)


def _generic_quoted_replacement(match: Match[str]) -> str | None:
    value = match.group("value")
    if _looks_like_placeholder(value):
        return None
    quote = match.group("quote")
    return f"{match.group('prefix')}{quote}{_marker('GENERIC_SECRET')}{quote}"


def _generic_bare_replacement(match: Match[str]) -> str | None:
    value = match.group("value")
    if _looks_like_placeholder(value):
        return None
    return f"{match.group('prefix')}{_marker('GENERIC_SECRET')}"


def _docker_auth_replacement(match: Match[str]) -> str | None:
    value = match.group("value")
    if _looks_like_placeholder(value):
        return None
    quote = match.group("quote")
    return f"{match.group('prefix')}{quote}{_marker('DOCKER_AUTH')}{quote}"


def _xml_secret_replacement(match: Match[str]) -> str | None:
    if _looks_like_placeholder(match.group("value")):
        return None
    return f"{match.group('open')}{_marker('XML_SECRET')}{match.group('close')}"


def _looks_like_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("'\"")
    lowered = cleaned.lower()
    if not cleaned or MARKER_PREFIX.lower() in lowered:
        return True
    exact = {
        "example",
        "sample",
        "changeme",
        "change_me",
        "replace_me",
        "replace-this",
        "dummy",
        "not-a-real",
        "not_a_real_secret",
    }
    if lowered in exact:
        return True
    if re.fullmatch(
        r"(?:your|insert|example|sample)[_-]"
        r"(?:openai[_-]?)?(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
        r"client[_-]?secret|password|passwd|secret|token|value)"
        r"(?:[_-]here)?",
        lowered,
    ):
        return True
    if cleaned.startswith(("${", "$env:", "{{", "<<")):
        return True
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", cleaned):
        return True
    if lowered.startswith(("os.environ", "process.env", "env.")):
        return True
    if cleaned.endswith(("_HERE", "-HERE")):
        return True
    if set(cleaned) <= {"*", "x", "X", "-", "_"}:
        return True
    return False


DETECTORS: tuple[Detector, ...] = (
    Detector(
        "PGP_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----\r?\n"
            r"[A-Za-z0-9+/=:\- .\r\n]{64,}?"
            r"-----END PGP PRIVATE KEY BLOCK-----",
            re.DOTALL,
        ),
    ),
    Detector(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----\r?\n"
            r"(?:[A-Za-z0-9-]+:[^\r\n]*\r?\n)*\r?\n?"
            r"(?:[A-Za-z0-9+/=]{16,}\r?\n){2,}"
            r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
        ),
    ),
    Detector(
        "OPENAI_API_KEY",
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    Detector(
        "GITHUB_TOKEN",
        re.compile(
            r"\b(?:gh[opsur]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
        ),
    ),
    Detector("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    Detector("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    Detector("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Detector(
        "STRIPE_SECRET_KEY",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
    ),
    Detector(
        "JWT",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
        ),
    ),
    Detector(
        "AUTHORIZATION",
        re.compile(
            r"(?i)(?P<prefix>\bAuthorization\s*:\s*)"
            r"(?P<scheme>Bearer|Basic)\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})"
        ),
        _authorization_replacement,
    ),
    Detector(
        "URL_CREDENTIALS",
        re.compile(
            r"(?P<scheme>\b[a-zA-Z][a-zA-Z0-9+.-]*://)"
            r"(?P<username>[^/\s:@]+):(?P<password>[^/\s@]+)@"
        ),
        _url_replacement,
    ),
    Detector(
        "DOCKER_AUTH",
        re.compile(
            r"(?im)(?P<prefix>['\"]auth['\"]\s*:\s*)"
            r"(?P<quote>['\"])(?P<value>[A-Za-z0-9+/]{12,}={0,2})(?P=quote)"
        ),
        _docker_auth_replacement,
    ),
    Detector(
        "XML_SECRET",
        re.compile(
            r"(?is)(?P<open><(?:password|passwd)>\s*)"
            r"(?P<value>[^<\r\n]{8,})"
            r"(?P<close>\s*</(?:password|passwd)>)"
        ),
        _xml_secret_replacement,
    ),
    Detector(
        "GENERIC_SECRET",
        re.compile(
            rf"(?im)(?P<prefix>['\"]?{SENSITIVE_KEY}['\"]?\s*[:=]\s*)"
            r"(?P<quote>['\"])(?P<value>[^'\"\r\n]{8,})(?P=quote)"
        ),
        _generic_quoted_replacement,
    ),
    Detector(
        "GENERIC_SECRET",
        re.compile(
            rf"(?im)(?P<prefix>\b{SENSITIVE_KEY}\b\s*[:=]\s*)"
            r"(?P<value>[^\s#,;]{8,})"
        ),
        _generic_bare_replacement,
    ),
)


def redact_text(text: str) -> RedactionResult:
    counts: dict[str, int] = {}
    redacted = text
    for detector in DETECTORS:
        redacted, count = detector.apply(redacted)
        if count:
            counts[detector.kind] = counts.get(detector.kind, 0) + count
    return RedactionResult(text=redacted, counts=dict(sorted(counts.items())))
