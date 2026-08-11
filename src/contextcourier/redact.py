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
    username = match.group("username")
    password = match.group("password")
    username_safe = not username or _looks_like_placeholder(username)
    password_safe = not password or _looks_like_placeholder(password)
    if username_safe and password_safe:
        return match.group(0)
    safe_username = username if username_safe else _marker("URL_USERNAME")
    safe_password = password if password_safe else _marker("URL_PASSWORD")
    return f"{match.group('scheme')}{safe_username}:{safe_password}@"


def _authorization_replacement(match: Match[str]) -> str | None:
    prefix = match.group("prefix") or ""
    quote = match.group("quote") or ""
    scheme = match.group("scheme")
    if _looks_like_placeholder(match.group("value")):
        return None
    return f"{prefix}{quote}{scheme} {_marker('AUTHORIZATION')}{quote}"


ASSIGNMENT_KEY = (
    r"(?<![A-Za-z0-9_-])['\"]?"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_-]{0,255})['\"]?"
    r"(?P<before_delimiter>[ \t]*+)(?P<delimiter>[:=])"
    r"(?P<after_delimiter>[ \t]*+)"
)
SENSITIVE_KEY_SUFFIXES = (
    "secretkeybase",
    "railsmasterkey",
    "secretaccesskey",
    "clientsecret",
    "accesstoken",
    "authtoken",
    "privatekey",
    "secretkey",
    "apikey",
    "password",
    "passwd",
    "secret",
    "token",
    "pwd",
)


def _is_sensitive_key(value: str) -> bool:
    compact = re.sub(r"[_-]+", "", value).casefold()
    return any(compact.endswith(suffix) for suffix in SENSITIVE_KEY_SUFFIXES)


TRIPLE_QUOTED_ASSIGNMENT = re.compile(
    rf"(?im)^(?P<indent>[ \t]*)(?P<prefix>{ASSIGNMENT_KEY})"
    r"(?P<triple>\"\"\"|''')"
)
YAML_BLOCK_ASSIGNMENT = re.compile(
    rf"(?i)^(?P<indent>[ \t]*)(?P<prefix>{ASSIGNMENT_KEY})"
    r"(?P<style>[|>])(?P<modifier>[0-9+-]{0,3})[ \t]*(?:#.*)?$"
)


def _generic_quoted_replacement(match: Match[str]) -> str | None:
    value = match.group("value")
    if not _is_sensitive_key(match.group("key")) or _looks_like_placeholder(value):
        return None
    quote = match.group("quote")
    return f"{match.group('prefix')}{quote}{_marker('GENERIC_SECRET')}{quote}"


def _generic_bare_replacement(match: Match[str]) -> str | None:
    value = match.group("value")
    if (
        not _is_sensitive_key(match.group("key"))
        or _looks_like_placeholder(value)
        or _looks_like_code_reference(match, value)
    ):
        return None
    return f"{match.group('prefix')}{_marker('GENERIC_SECRET')}"


def _looks_like_code_reference(match: Match[str], value: str) -> bool:
    delimiter = match.group("delimiter")
    cleaned = value.strip()
    if delimiter == ":":
        if (" | " in cleaned or " = " in cleaned) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_.]*(?:\[[^\r\n]+\])?"
            r"(?:\s*\|\s*[A-Za-z_][A-Za-z0-9_.]*(?:\[[^\r\n]+\])?)*"
            r"(?:\s*=\s*.+)?",
            cleaned,
        ):
            return True
        return False
    if delimiter != "=":
        return False
    if match.group("key").startswith("_"):
        structural = cleaned.rstrip(",)]}")
        if re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
            structural,
        ):
            return True
    if not (match.group("before_delimiter") or match.group("after_delimiter")):
        return False
    if re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+",
        cleaned,
    ):
        return True
    if re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
        r"\([^()\r\n]*\)",
        cleaned,
    ):
        return True
    if re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.]*\s+if\s+.+\s+else\s+.+",
        cleaned,
    ):
        return True
    key = match.group("key").casefold()
    return bool(
        key.startswith(("safe_", "source_", "expected_", "current_"))
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cleaned)
    )


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
    if not cleaned:
        return True
    if re.fullmatch(r"<<CONTEXTCOURIER_REDACTED:[A-Z0-9_]+>>", cleaned):
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
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", cleaned):
        return True
    if re.fullmatch(r"(?i)\$env:[A-Za-z_][A-Za-z0-9_]*", cleaned):
        return True
    if re.fullmatch(
        r"\{\{\s*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\}\}",
        cleaned,
    ):
        return True
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", cleaned):
        return True
    if re.fullmatch(
        r"(?i)(?:os\.environ(?:\[['\"][A-Za-z_][A-Za-z0-9_]*['\"]\]|"
        r"\.get\(['\"][A-Za-z_][A-Za-z0-9_]*['\"]\))|"
        r"process\.env\.[A-Za-z_][A-Za-z0-9_]*|env\.[A-Za-z_][A-Za-z0-9_]*)",
        cleaned,
    ):
        return True
    if set(cleaned) <= {"*", "x", "X", "-", "_"}:
        return True
    return False


DETECTORS: tuple[Detector, ...] = (
    Detector(
        "PGP_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----\r?\n"
            r"(?>[A-Za-z0-9+/=: .\r\n]{64,})"
            r"-----END PGP PRIVATE KEY BLOCK-----",
        ),
    ),
    Detector(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN(?P<label>(?: [A-Z0-9]+)?) PRIVATE KEY-----\r?\n"
            r"(?:[A-Za-z0-9-]+:[^\r\n]*\r?\n)*\r?\n?"
            r"(?>[A-Za-z0-9+/=]{4,}\r?\n)+"
            r"-----END(?P=label) PRIVATE KEY-----",
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
            r"(?i)(?P<prefix>['\"]?Authorization['\"]?\s*:\s*)"
            r"(?P<quote>['\"]?)(?P<scheme>Bearer|Basic)\s+"
            r"(?P<value>[A-Za-z0-9._~+/=-]{4,})(?P=quote)"
        ),
        _authorization_replacement,
    ),
    Detector(
        "URL_CREDENTIALS",
        re.compile(
            r"(?P<scheme>\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://)"
            r"(?P<username>[^/\s:@]{0,8192}):(?P<password>[^/\s@]{0,8192})@"
        ),
        _url_replacement,
    ),
    Detector(
        "DOCKER_AUTH",
        re.compile(
            r"(?im)(?P<prefix>['\"]auth['\"]\s*:\s*)"
            r"(?P<quote>['\"])(?P<value>[A-Za-z0-9+/]{4,}={0,2})(?P=quote)"
        ),
        _docker_auth_replacement,
    ),
    Detector(
        "XML_SECRET",
        re.compile(
            r"(?is)(?P<open><(?:password|passwd)>\s*)"
            r"(?P<value>[^<\r\n]{1,})"
            r"(?P<close>\s*</(?:password|passwd)>)"
        ),
        _xml_secret_replacement,
    ),
    Detector(
        "GENERIC_SECRET",
        re.compile(
            rf"(?im)(?P<prefix>{ASSIGNMENT_KEY})"
            r'(?P<quote>")'
            r"(?P<value>(?>\\[^\r\n]|[^\"\\\r\n]){1,})(?P=quote)"
        ),
        _generic_quoted_replacement,
    ),
    Detector(
        "GENERIC_SECRET",
        re.compile(
            rf"(?im)(?P<prefix>{ASSIGNMENT_KEY})"
            r"(?P<quote>')"
            r"(?P<value>(?>''|\\[^\r\n]|[^'\\\r\n]){1,})(?P=quote)"
        ),
        _generic_quoted_replacement,
    ),
    Detector(
        "GENERIC_SECRET",
        re.compile(
            rf"(?im)(?P<prefix>{ASSIGNMENT_KEY})"
            r"(?P<value>(?!['\"])[^\r\n]{1,})"
        ),
        _generic_bare_replacement,
    ),
)


def _redact_putty_private_lines(text: str) -> tuple[str, int]:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    index = 0
    header_index: int | None = None
    count = 0
    while index < len(lines):
        stripped = lines[index].rstrip("\r\n")
        if re.fullmatch(r"PuTTY-User-Key-File-[23]:[^\r\n]+", stripped):
            header_index = index
        private_match = re.fullmatch(r"Private-Lines:\s*([0-9]{1,6})", stripped)
        if (
            header_index is not None
            and index - header_index <= 200
            and private_match is not None
        ):
            line_count = int(private_match.group(1))
            body = lines[index + 1 : index + 1 + line_count]
            following = index + 1 + line_count
            valid_body = (
                0 < line_count <= 100_000
                and len(body) == line_count
                and all(
                    re.fullmatch(r"[A-Za-z0-9+/=]{4,}\r?\n?", item) is not None
                    for item in body
                )
                and following < len(lines)
                and lines[following].startswith("Private-MAC:")
            )
            if valid_body:
                output.append(lines[index])
                newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
                output.append(_marker("PUTTY_PRIVATE_KEY") + newline)
                index = following
                count += 1
                header_index = None
                continue
        output.append(lines[index])
        if header_index is not None and index - header_index > 200:
            header_index = None
        index += 1
    return "".join(output), count


def _redact_triple_quoted_assignments(text: str) -> tuple[str, int]:
    output: list[str] = []
    cursor = 0
    search_from = 0
    count = 0
    while True:
        match = TRIPLE_QUOTED_ASSIGNMENT.search(text, search_from)
        if match is None:
            break
        if not _is_sensitive_key(match.group("key")):
            search_from = match.end()
            continue
        triple = match.group("triple")
        closing = _find_unescaped(text, triple, match.end())
        block_end = len(text) if closing < 0 else closing + len(triple)
        value = text[match.end() : block_end if closing < 0 else closing]
        if _looks_like_placeholder(value.strip()):
            search_from = block_end
            continue
        output.append(text[cursor : match.start()])
        output.append(
            f'{match.group("indent")}{match.group("prefix")}"'
            f'{_marker("GENERIC_SECRET")}"'
        )
        cursor = block_end
        search_from = block_end
        count += 1
    if not count:
        return text, 0
    output.append(text[cursor:])
    return "".join(output), count


def _find_unescaped(text: str, needle: str, start: int) -> int:
    position = start
    while True:
        position = text.find(needle, position)
        if position < 0:
            return -1
        backslashes = 0
        cursor = position - 1
        while cursor >= start and text[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return position
        position += len(needle)


def _redact_yaml_block_assignments(text: str) -> tuple[str, int]:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    index = 0
    count = 0
    while index < len(lines):
        line = lines[index]
        core = line.rstrip("\r\n")
        match = YAML_BLOCK_ASSIGNMENT.fullmatch(core)
        if match is None or not _is_sensitive_key(match.group("key")):
            output.append(line)
            index += 1
            continue
        base_indent = len(match.group("indent"))
        following = index + 1
        first_content_indent: str | None = None
        while following < len(lines):
            candidate_core = lines[following].rstrip("\r\n")
            if not candidate_core.strip():
                following += 1
                continue
            indentation = candidate_core[: len(candidate_core) - len(candidate_core.lstrip(" \t"))]
            if len(indentation) <= base_indent:
                break
            if first_content_indent is None:
                first_content_indent = indentation
            following += 1
        if following == index + 1:
            output.append(line)
            index += 1
            continue
        value = "".join(lines[index + 1 : following]).strip()
        if _looks_like_placeholder(value):
            output.extend(lines[index:following])
            index = following
            continue
        newline = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
        output.append(
            f'{match.group("indent")}{match.group("prefix")}"'
            f'{_marker("GENERIC_SECRET")}"{newline}'
        )
        index = following
        count += 1
    return "".join(output), count


def redact_text(text: str) -> RedactionResult:
    counts: dict[str, int] = {}
    redacted, putty_count = _redact_putty_private_lines(text)
    if putty_count:
        counts["PUTTY_PRIVATE_KEY"] = putty_count
    redacted, triple_count = _redact_triple_quoted_assignments(redacted)
    redacted, yaml_count = _redact_yaml_block_assignments(redacted)
    if triple_count or yaml_count:
        counts["GENERIC_SECRET"] = triple_count + yaml_count
    for detector in DETECTORS:
        redacted, count = detector.apply(redacted)
        if count:
            counts[detector.kind] = counts.get(detector.kind, 0) + count
    return RedactionResult(text=redacted, counts=dict(sorted(counts.items())))
