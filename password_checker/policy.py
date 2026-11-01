"""Historical ASCII composition requirements, not security recommendations.

Upper/lower/digit mean A-Z/a-z/0-9 only. The historical 'special' regex
matches anything outside those ASCII ranges, including spaces and Unicode
letters. Unicode characters receive no strength points (there is no score).
"""

import re

from .models import Criterion, CriterionResult, PolicyId, PolicyResult

_PATTERNS = (
    (Criterion.UPPERCASE, re.compile(r"[A-Z]")),
    (Criterion.LOWERCASE, re.compile(r"[a-z]")),
    (Criterion.DIGIT, re.compile(r"[0-9]")),
    (Criterion.SPECIAL, re.compile(r"[^A-Za-z0-9]")),
)


def _evaluate_legacy_policy(password: str) -> PolicyResult:
    """Internal: core must validate input before calling this helper."""
    criteria = (CriterionResult(Criterion.LENGTH, len(password) >= 8),) + tuple(
        CriterionResult(criterion, bool(pattern.search(password)))
        for criterion, pattern in _PATTERNS
    )
    return PolicyResult(PolicyId.LEGACY_ASCII_COMPOSITION, criteria)
