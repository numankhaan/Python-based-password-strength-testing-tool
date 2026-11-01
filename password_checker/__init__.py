"""Local password policy checking; no strength estimator is included."""

from .core import assess_password

__all__ = ["assess_password"]
