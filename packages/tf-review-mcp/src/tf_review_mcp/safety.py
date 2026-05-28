"""Host-policy guards for plan file reads.

Env-driven, set by the host running the server. Not part of `.tf-review.yml`
because policy here is about the host filesystem, not the team's review
rules. The v1 stdio transport defaults are permissive on purpose (the
trust boundary is the developer's machine); these knobs let an operator
tighten that for the upcoming HTTP transport.

Two settings:

  TF_REVIEW_ALLOWED_DIRS
      Colon-separated list of directory prefixes. When set, plan paths
      must resolve under one of these prefixes. When unset, any readable
      path is permitted.

  TF_REVIEW_MAX_PLAN_BYTES
      Max plan-file size in bytes. Default 50MB. Override with a positive
      integer; any other value falls back to the default rather than
      crashing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

DEFAULT_MAX_PLAN_BYTES = 50 * 1024 * 1024


class PolicyError(ValueError):
    """Raised when a plan path violates host policy."""


def _max_plan_bytes() -> int:
    raw = os.environ.get("TF_REVIEW_MAX_PLAN_BYTES")
    if raw is None:
        return DEFAULT_MAX_PLAN_BYTES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_PLAN_BYTES
    if value <= 0:
        return DEFAULT_MAX_PLAN_BYTES
    return value


def _allowed_dirs() -> list[Path]:
    raw = os.environ.get("TF_REVIEW_ALLOWED_DIRS")
    if not raw:
        return []
    out: list[Path] = []
    for piece in raw.split(":"):
        piece = piece.strip()
        if not piece:
            continue
        out.append(Path(piece).expanduser().resolve())
    return out


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_plan_path(path: str | Path) -> Path:
    """Resolve a candidate plan path and validate against host policy.

    Performs three checks:
      1. Reject NUL bytes in the input.
      2. If TF_REVIEW_ALLOWED_DIRS is set, the resolved path must live
         under one of the listed prefixes.
      3. If the file exists, its size must be <= TF_REVIEW_MAX_PLAN_BYTES.

    Raises `PolicyError` on a policy failure. Returns the resolved Path
    on success. Existence is not checked here; callers can handle
    FileNotFoundError naturally on a subsequent open.
    """
    if isinstance(path, str) and "\x00" in path:
        raise PolicyError("plan path contains NUL byte")

    candidate = Path(path).expanduser().resolve()

    allowed = _allowed_dirs()
    if allowed and not any(_is_within(candidate, root) for root in allowed):
        raise PolicyError(
            f"plan path {candidate} is outside TF_REVIEW_ALLOWED_DIRS "
            f"({len(allowed)} prefix(es) configured)"
        )

    if candidate.exists() and candidate.is_file():
        size = candidate.stat().st_size
        cap = _max_plan_bytes()
        if size > cap:
            raise PolicyError(
                f"plan file size {size} bytes exceeds "
                f"TF_REVIEW_MAX_PLAN_BYTES={cap}"
            )

    return candidate


def policy_snapshot() -> dict[str, Any]:
    """Return the active host policy. Used by get_active_config."""
    allowed = _allowed_dirs()
    return {
        "max_plan_bytes": _max_plan_bytes(),
        "allowed_dirs": [str(p) for p in allowed] if allowed else None,
    }
