"""Validate exact input without copying, normalizing, or echoing it."""

import unicodedata

from .models import ReasonCode, UnicodeClass

MAX_INPUT_CODE_POINTS = 1024  # Application processing cap, not a security rule.
_LINE_BREAKS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
_UNICODE_CLASSES = {
    "L": UnicodeClass.LETTER,
    "M": UnicodeClass.MARK,
    "N": UnicodeClass.NUMBER,
    "P": UnicodeClass.PUNCTUATION,
    "S": UnicodeClass.SYMBOL,
    "Z": UnicodeClass.SEPARATOR,
    "C": UnicodeClass.OTHER,
}


def validate_input(value: object) -> ReasonCode:
    """Return a safe reason code; reject invalid input before policy evaluation.

    Lengths are Python Unicode code points. All Cc controls, line breaks
    (including Zl/Zp), and Cs surrogates are rejected. Other categories,
    including Cf format characters, are preserved and accepted.
    """
    if not isinstance(value, str):
        return ReasonCode.WRONG_TYPE
    if not value:
        return ReasonCode.EMPTY
    if len(value) > MAX_INPUT_CODE_POINTS:
        return ReasonCode.TOO_LONG
    # A fixed priority makes mixed invalid inputs deterministic.
    if any(char in _LINE_BREAKS for char in value):
        return ReasonCode.LINE_BREAK
    if any(unicodedata.category(char) == "Cs" for char in value):
        return ReasonCode.SURROGATE
    if any(unicodedata.category(char) == "Cc" for char in value):
        return ReasonCode.CONTROL
    return ReasonCode.VALID


def classify_unicode(value: str) -> tuple[UnicodeClass, ...]:
    """Informational category presence only; never a strength score."""
    present = {_UNICODE_CLASSES[unicodedata.category(char)[0]] for char in value}
    return tuple(item for item in UnicodeClass if item in present)
