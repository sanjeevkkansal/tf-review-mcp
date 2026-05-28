"""Sanitize untrusted input before it reaches a language model.

Two public functions:

  sanitize_for_model(value, *, max_len=512) -> str
      Strip control/format characters, truncate to a bounded length, and
      annotate lines whose start matches a known prompt-injection
      preamble with a "[sus]" marker. The original line content is
      preserved; we never silently rewrite suspicious text.

  sanitize_address(addr) -> str
      Validate a dotted resource address. Reject path-traversal
      characters that have no business appearing in one.

Conservative by design. Surprises are worse than wordiness; this module
marks suspicious content rather than rewriting it.
"""

from __future__ import annotations

import unicodedata

DEFAULT_MAX_LEN = 512
TRUNCATION_MARKER = "...[truncated]"
SUSPICIOUS_MARKER = "[sus]"

_SUSPICIOUS_LINE_PREFIXES: tuple[str, ...] = (
    "system:",
    "assistant:",
    "user:",
    "ignore previous",
    "ignore prior",
    "ignore all previous",
    "disregard ",
    "you are now",
    "new instructions",
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|assistant|>",
    "<|user|>",
)

_PATH_TRAVERSAL_TOKENS: tuple[str, ...] = ("..", "/", "\\", "\x00")


def _is_control(ch: str) -> bool:
    if ch in ("\t", "\n"):
        return False
    return unicodedata.category(ch) in ("Cc", "Cf")


def _strip_control_chars(s: str) -> str:
    return "".join(ch for ch in s if not _is_control(ch))


def sanitize_for_model(value: str, *, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Sanitize a string that will be shown to a language model.

    Steps, in order:
      1. Coerce to str.
      2. Strip Unicode Cc/Cf characters (keep tab and newline).
      3. Prefix lines that begin with a known injection preamble with the
         "[sus]" marker. The original line content is preserved verbatim
         after the marker.
      4. Truncate to `max_len` characters with a trailing marker if needed.
    """
    if max_len <= 0:
        raise ValueError("max_len must be positive")
    if not isinstance(value, str):
        value = str(value)

    cleaned = _strip_control_chars(value)

    annotated_lines: list[str] = []
    for line in cleaned.splitlines():
        stripped = line.lstrip().lower()
        if any(stripped.startswith(p) for p in _SUSPICIOUS_LINE_PREFIXES):
            annotated_lines.append(f"{SUSPICIOUS_MARKER} {line}")
        else:
            annotated_lines.append(line)
    result = "\n".join(annotated_lines)

    if len(result) > max_len:
        keep = max(0, max_len - len(TRUNCATION_MARKER))
        result = result[:keep] + TRUNCATION_MARKER
    return result


def sanitize_address(addr: str) -> str:
    """Validate a dotted resource address. Returns the trimmed address.

    Raises `ValueError` if the address contains a NUL byte, a forward or
    back slash, or a parent-directory token. Terraform / cloud resource
    addresses are dotted (`module.foo.aws_instance.bar`); any of those
    tokens indicates a path-traversal attempt, not a legitimate address.
    """
    if not isinstance(addr, str):
        raise ValueError(f"address must be str, got {type(addr).__name__}")
    if "\x00" in addr:
        raise ValueError("address contains NUL byte")
    for bad in _PATH_TRAVERSAL_TOKENS:
        if bad in addr:
            raise ValueError(f"address contains forbidden token {bad!r}")
    return addr.strip()


def sanitize_address_or_marker(addr: str) -> str:
    """Best-effort variant for callers that should never raise.

    Returns the sanitized address if valid, otherwise returns a redacted
    placeholder string. Suitable for serializing fields where raising
    would crash the response.
    """
    try:
        return sanitize_address(addr)
    except ValueError:
        return "[invalid-address]"
