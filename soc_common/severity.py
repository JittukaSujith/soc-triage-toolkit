"""Severity levels shared by all tools.

SOC teams rank work by severity so the scariest things get looked at first.
Using one enum everywhere keeps scores and labels consistent between tools.
"""
from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value) -> "Severity":
        """Accept a Severity, an int 0-4, or a name like 'high' (any case)."""
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            try:
                return cls(value)
            except ValueError:
                raise ValueError("severity number must be between 0 and 4, got %r" % value)
        text = str(value).strip().upper()
        if text in cls.__members__:
            return cls[text]
        raise ValueError(
            "unknown severity %r (use one of: %s)" % (value, ", ".join(m.lower() for m in cls.__members__))
        )

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Convert a 0-100 risk score into a severity level."""
        if score >= 80:
            return cls.CRITICAL
        if score >= 60:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 20:
            return cls.LOW
        return cls.INFO

    @property
    def label(self) -> str:
        return self.name

    def bump(self, levels: int = 1) -> "Severity":
        """Return a higher severity (capped at CRITICAL)."""
        return Severity(min(int(self) + levels, int(Severity.CRITICAL)))
