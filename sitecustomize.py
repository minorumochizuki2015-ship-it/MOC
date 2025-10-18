"""Sitecustomize hook for deterministic timestamps.

If the environment variable FIXED_UTC is set to an ISO-8601 datetime
(e.g. "2024-01-01T00:00:00Z"), this module monkey-patches
`datetime.datetime.now` and `datetime.datetime.utcnow` so that they
always return the fixed value.  This ensures reproducible timestamps in
unit tests and other deterministic contexts.

The patch is applied as early as possible because Python automatically
imports `sitecustomize` once it's discoverable on `sys.path`.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

_FIXED_ENV = "FIXED_UTC"

_fixed_value = os.getenv(_FIXED_ENV)
if _fixed_value:
    # Normalise Z suffix to +00:00 for fromisoformat compatibility
    if _fixed_value.endswith("Z"):
        _fixed_value = _fixed_value[:-1] + "+00:00"

    try:
        _FIXED_DT = datetime.fromisoformat(_fixed_value).astimezone(timezone.utc)
    except ValueError:
        # Invalid format ➜ fail fast to surface misconfiguration
        raise RuntimeError(
            f"Environment variable {_FIXED_ENV} has invalid ISO-8601 value: {_fixed_value!r}"
        ) from None

    class _FixedDateTimeMeta(type):
        """Metaclass to keep isinstance checks working."""

        def __instancecheck__(cls, instance):  # noqa: D401,E501 – simple passthrough
            return isinstance(instance, datetime)

    class FixedDateTime(datetime, metaclass=_FixedDateTimeMeta):
        """datetime subclass with deterministic now()/utcnow()."""

        @classmethod  # type: ignore[override]
        def now(cls, tz: timezone | None = None):  # noqa: N804 – override built-in name
            if tz is None:
                return _FIXED_DT.replace(tzinfo=None)
            return _FIXED_DT.astimezone(tz)

        @classmethod  # type: ignore[override]
        def utcnow(cls):  # noqa: N804 – override built-in name
            # Historical behaviour of utcnow() returns naive datetime
            return _FIXED_DT.replace(tzinfo=None)

    # Monkey-patch in the deterministic subclass
    sys.modules["datetime"].datetime = FixedDateTime
