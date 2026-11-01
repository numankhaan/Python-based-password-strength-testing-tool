"""Headless assessment API. No GUI, I/O, persistence, or strength estimator."""

from .models import AssessmentResult, AssessmentStatus, ReasonCode
from .policy import _evaluate_legacy_policy
from .validation import classify_unicode, validate_input


def assess_password(password: object) -> AssessmentResult:
    """Check exact input and return only safe policy/category metadata.

    Invalid or empty input returns a structured result, never an input-bearing
    validation exception. Strength is always not_assessed in Phase 1.
    """
    reason = validate_input(password)
    if reason is not ReasonCode.VALID:
        status = (AssessmentStatus.EMPTY_INPUT if reason is ReasonCode.EMPTY
                  else AssessmentStatus.INVALID_INPUT)
        return AssessmentResult(status, reason)
    return AssessmentResult(
        AssessmentStatus.POLICY_EVALUATED,
        ReasonCode.VALID,
        _evaluate_legacy_policy(password),
        classify_unicode(password),
    )
