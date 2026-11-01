"""Allowlisted results: no input, substrings, context, or hashes are retained."""

from dataclasses import dataclass
from enum import Enum


class AssessmentStatus(str, Enum):
    POLICY_EVALUATED = "policy_evaluated"
    EMPTY_INPUT = "empty_input"
    INVALID_INPUT = "invalid_input"


class StrengthStatus(str, Enum):
    NOT_ASSESSED = "not_assessed"


class ComplianceStatus(str, Enum):
    MEETS = "meets_configured_requirements"
    DOES_NOT_MEET = "does_not_meet_configured_requirements"
    NOT_EVALUATED = "not_evaluated"


class ReasonCode(str, Enum):
    VALID = "valid"
    EMPTY = "empty_input"
    WRONG_TYPE = "invalid_type"
    TOO_LONG = "input_limit_exceeded"
    CONTROL = "control_character"
    LINE_BREAK = "line_break"
    SURROGATE = "isolated_surrogate"


REASON_MESSAGES = {
    ReasonCode.VALID: "Legacy composition policy evaluated. Strength not assessed.",
    ReasonCode.EMPTY: "Enter a password. Policy not evaluated. Strength not assessed.",
    ReasonCode.WRONG_TYPE: "Input must be a string. Policy not evaluated. Strength not assessed.",
    ReasonCode.TOO_LONG: "Input exceeds the 1024-code-point processing limit. Policy not evaluated. Strength not assessed.",
    ReasonCode.CONTROL: "Control characters are not accepted. Policy not evaluated. Strength not assessed.",
    ReasonCode.LINE_BREAK: "Line breaks are not accepted. Policy not evaluated. Strength not assessed.",
    ReasonCode.SURROGATE: "Isolated surrogates are not accepted. Policy not evaluated. Strength not assessed.",
}


class PolicyId(str, Enum):
    LEGACY_ASCII_COMPOSITION = "legacy_ascii_composition"


class Criterion(str, Enum):
    LENGTH = "at_least_8_code_points"
    UPPERCASE = "ascii_uppercase"
    LOWERCASE = "ascii_lowercase"
    DIGIT = "ascii_digit"
    SPECIAL = "outside_ascii_alphanumeric"


class UnicodeClass(str, Enum):
    LETTER = "letter"
    MARK = "mark"
    NUMBER = "number"
    PUNCTUATION = "punctuation"
    SYMBOL = "symbol"
    SEPARATOR = "separator"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class CriterionResult:
    criterion: Criterion
    met: bool

    def __post_init__(self):
        if type(self.criterion) is not Criterion or type(self.met) is not bool:
            raise ValueError("Invalid criterion result fields.")


@dataclass(frozen=True, slots=True)
class PolicyResult:
    policy_id: PolicyId
    criteria: tuple[CriterionResult, ...]

    def __post_init__(self):
        if (
            type(self.policy_id) is not PolicyId
            or type(self.criteria) is not tuple
            or any(type(item) is not CriterionResult for item in self.criteria)
            or tuple(item.criterion for item in self.criteria) != tuple(Criterion)
        ):
            raise ValueError("Invalid policy result fields.")

    @property
    def compliance(self) -> ComplianceStatus:
        if all(item.met for item in self.criteria):
            return ComplianceStatus.MEETS
        return ComplianceStatus.DOES_NOT_MEET


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    status: AssessmentStatus
    reason: ReasonCode
    policy: PolicyResult | None = None
    unicode_classes: tuple[UnicodeClass, ...] = ()

    def __post_init__(self):
        if (
            type(self.status) is not AssessmentStatus
            or type(self.reason) is not ReasonCode
            or (self.policy is not None and type(self.policy) is not PolicyResult)
            or type(self.unicode_classes) is not tuple
            or any(type(item) is not UnicodeClass for item in self.unicode_classes)
        ):
            raise ValueError("Invalid assessment result fields.")
        if self.reason is ReasonCode.VALID:
            expected_status = AssessmentStatus.POLICY_EVALUATED
        elif self.reason is ReasonCode.EMPTY:
            expected_status = AssessmentStatus.EMPTY_INPUT
        else:
            expected_status = AssessmentStatus.INVALID_INPUT
        if (
            self.status is not expected_status
            or (self.policy is not None) != (self.reason is ReasonCode.VALID)
            or (self.reason is not ReasonCode.VALID and self.unicode_classes)
        ):
            raise ValueError("Inconsistent assessment result fields.")

    @property
    def strength(self) -> StrengthStatus:
        return StrengthStatus.NOT_ASSESSED

    @property
    def compliance(self) -> ComplianceStatus:
        return self.policy.compliance if self.policy else ComplianceStatus.NOT_EVALUATED

    @property
    def message(self) -> str:
        return REASON_MESSAGES[self.reason]

    def to_dict(self) -> dict:
        """Return only allowlisted, JSON-compatible assessment data."""
        return {
            "status": self.status.value,
            "reason": self.reason.value,
            "message": self.message,
            "strength": self.strength.value,
            "compliance": self.compliance.value,
            "policy": None if self.policy is None else {
                "policy_id": self.policy.policy_id.value,
                "criteria": [
                    {"criterion": item.criterion.value, "met": item.met}
                    for item in self.policy.criteria
                ],
            },
            "unicode_classes": [item.value for item in self.unicode_classes],
        }
