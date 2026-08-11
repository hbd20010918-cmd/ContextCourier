"""Domain-specific exceptions used by the CLI."""

from __future__ import annotations


class ContextCourierError(Exception):
    """Base error for expected, user-actionable failures."""


class ConfigError(ContextCourierError):
    """Raised when project configuration is invalid."""


class ScanError(ContextCourierError):
    """Raised when the source project cannot be scanned safely."""


class VerificationError(ContextCourierError):
    """Raised when an archive fails integrity or path-safety checks."""


class SecretPolicyError(ContextCourierError):
    """Raised when fail-on-secret mode detects sensitive content."""
