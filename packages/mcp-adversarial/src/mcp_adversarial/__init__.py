"""Adversarial input harness for MCP servers."""

from .sanitize import (
    DEFAULT_MAX_LEN,
    SUSPICIOUS_MARKER,
    TRUNCATION_MARKER,
    sanitize_address,
    sanitize_address_or_marker,
    sanitize_for_model,
)

__version__ = "0.0.0"

__all__ = [
    "DEFAULT_MAX_LEN",
    "SUSPICIOUS_MARKER",
    "TRUNCATION_MARKER",
    "sanitize_address",
    "sanitize_address_or_marker",
    "sanitize_for_model",
    "__version__",
]
