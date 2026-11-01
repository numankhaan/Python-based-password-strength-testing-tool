"""Behavioral regressions using synthetic inputs only."""

import dataclasses
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from password_checker.core import assess_password
from password_checker.models import (
    AssessmentResult, AssessmentStatus, ComplianceStatus, Criterion,
    CriterionResult, PolicyId, PolicyResult, ReasonCode, StrengthStatus, UnicodeClass,
)
from password_checker.validation import MAX_INPUT_CODE_POINTS

ROOT = Path(__file__).resolve().parents[1]


def criteria(result):
    return {item.criterion: item.met for item in result.policy.criteria}


class CoreTests(unittest.TestCase):
    def test_headless_imports_have_no_output_gui_network_or_writes(self):
        # A fresh interpreter catches accidental imports hidden by module caching.
        code = r'''
import sys
sys.dont_write_bytecode = True
violations = []
def guard(event, args):
    forbidden = event.startswith('socket.') or event in (
        'os.mkdir', 'os.remove', 'os.rename', 'os.rmdir', 'os.truncate',
        'os.chmod', 'os.link', 'os.symlink', 'os.system', 'subprocess.Popen',
    )
    if event == 'import' and args[0].split('.')[0] in ('tkinter', '_tkinter'):
        forbidden = True
    if event == 'open':
        mode, flags = args[1], args[2]
        forbidden |= bool(mode and any(c in mode for c in 'wax+'))
        forbidden |= bool(flags & 3)  # O_WRONLY or O_RDWR
    if forbidden:
        violations.append(event)
        raise AssertionError('Forbidden side effect: ' + event)
sys.addaudithook(guard)
import password_checker.core
import password_checker.models
import password_checker.validation
import password_checker.policy
import Password_Strength_Checker
assert 'tkinter' not in sys.modules
assert '_tkinter' not in sys.modules
assert not violations
'''
        completed = subprocess.run(
            [sys.executable, '-B', '-c', code], cwd=ROOT,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, '')
        self.assertEqual(completed.stderr, '')

    def test_each_legacy_requirement_matters(self):
        self.assertIs(assess_password('Abcdef1!').compliance, ComplianceStatus.MEETS)
        examples = {
            Criterion.LENGTH: 'Abcde1!',
            Criterion.UPPERCASE: 'abcdef1!',
            Criterion.LOWERCASE: 'ABCDEF1!',
            Criterion.DIGIT: 'Abcdefg!',
            Criterion.SPECIAL: 'Abcdef12',
        }
        for missing, password in examples.items():
            with self.subTest(missing=missing):
                result = assess_password(password)
                self.assertIs(result.compliance, ComplianceStatus.DOES_NOT_MEET)
                self.assertEqual([key for key, met in criteria(result).items() if not met], [missing])
                self.assertIs(result.policy.policy_id, PolicyId.LEGACY_ASCII_COMPOSITION)

    def test_policy_and_processing_length_boundaries(self):
        for length, length_met in [(1, False), (7, False), (8, True), (9, True), (1024, True)]:
            with self.subTest(length=length):
                result = assess_password('a' * length)
                self.assertIs(result.status, AssessmentStatus.POLICY_EVALUATED)
                self.assertEqual(criteria(result)[Criterion.LENGTH], length_met)
        self.assertEqual(MAX_INPUT_CODE_POINTS, 1024)
        with patch('password_checker.core._evaluate_legacy_policy') as policy:
            result = assess_password('Abcdef1!' + 'a' * 1017)
            self.assertIs(result.reason, ReasonCode.TOO_LONG)
            self.assertIsNone(result.policy)
            policy.assert_not_called()

    def test_empty_wrong_type_and_over_limit_are_not_evaluated(self):
        class Unprintable:
            def __repr__(self):
                raise AssertionError('Must not format input')
            __str__ = __repr__

        cases = [('', ReasonCode.EMPTY), (None, ReasonCode.WRONG_TYPE),
                 (42, ReasonCode.WRONG_TYPE), (b'Abcdef1!', ReasonCode.WRONG_TYPE),
                 (['synthetic'], ReasonCode.WRONG_TYPE), (Unprintable(), ReasonCode.WRONG_TYPE),
                 ('x' * 1025, ReasonCode.TOO_LONG)]
        for value, reason in cases:
            with self.subTest(reason=reason):
                result = assess_password(value)
                self.assertIs(result.reason, reason)
                self.assertIs(result.compliance, ComplianceStatus.NOT_EVALUATED)
                self.assertIs(result.strength, StrengthStatus.NOT_ASSESSED)
                self.assertIsNone(result.policy)
                self.assertEqual(result.unicode_classes, ())

    def test_exact_input_including_spaces_is_preserved(self):
        self.assertIs(assess_password('        ').status, AssessmentStatus.POLICY_EVALUATED)
        self.assertTrue(criteria(assess_password('        '))[Criterion.SPECIAL])
        self.assertFalse(criteria(assess_password('Abcde1!'))[Criterion.LENGTH])
        self.assertIs(assess_password(' Abcde1!').compliance, ComplianceStatus.MEETS)
        self.assertIs(assess_password('Abcde1! ').compliance, ComplianceStatus.MEETS)
        self.assertFalse(criteria(assess_password('Abcdef12'))[Criterion.SPECIAL])
        self.assertTrue(criteria(assess_password('Abcdef12 '))[Criterion.SPECIAL])

    def test_unicode_categories_are_information_only(self):
        cases = [
            ('é', UnicodeClass.LETTER), ('漢字', UnicodeClass.LETTER),
            ('عربى', UnicodeClass.LETTER), ('😀', UnicodeClass.SYMBOL),
            ('\u0301', UnicodeClass.MARK), ('٣', UnicodeClass.NUMBER),
            ('\u00a0', UnicodeClass.SEPARATOR), ('\u200d', UnicodeClass.OTHER),
        ]
        for value, category in cases:
            with self.subTest(category=category):
                result = assess_password(value)
                self.assertEqual(result.unicode_classes, (category,))
                self.assertEqual(criteria(result), {
                    Criterion.LENGTH: False, Criterion.UPPERCASE: False,
                    Criterion.LOWERCASE: False, Criterion.DIGIT: False, Criterion.SPECIAL: True,
                })
                self.assertIs(result.strength, StrengthStatus.NOT_ASSESSED)
        self.assertFalse(criteria(assess_password('É' * 8))[Criterion.UPPERCASE])
        # Eight code points, four rendered graphemes: no normalization occurs.
        self.assertFalse(criteria(assess_password('é' * 4))[Criterion.LENGTH])
        self.assertTrue(criteria(assess_password('e\u0301' * 4))[Criterion.LENGTH])
        self.assertFalse(criteria(assess_password('😀' * 7))[Criterion.LENGTH])
        self.assertTrue(criteria(assess_password('😀' * 8))[Criterion.LENGTH])
        self.assertIs(assess_password('😀' * 1024).status, AssessmentStatus.POLICY_EVALUATED)
        self.assertIs(assess_password('😀' * 1025).reason, ReasonCode.TOO_LONG)

    def test_controls_line_breaks_and_surrogates(self):
        cases = [(char, ReasonCode.LINE_BREAK) for char in '\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029']
        cases += [(char, ReasonCode.CONTROL) for char in '\0\t\x1b\x7f\x80\x9f']
        cases += [(char, ReasonCode.SURROGATE) for char in ('\ud800', '\udfff', '\ud83d\ude00')]
        for char, reason in cases:
            with self.subTest(code_points=tuple(map(ord, char))):
                result = assess_password('Abcdef1!' + char)
                self.assertIs(result.reason, reason)
                self.assertIsNone(result.policy)
                self.assertIs(result.strength, StrengthStatus.NOT_ASSESSED)

    def test_old_misleading_examples_never_get_strength_claims(self):
        for password, compliance in [('Aa1!', ComplianceStatus.DOES_NOT_MEET),
                                     ('Password1!', ComplianceStatus.MEETS)]:
            result = assess_password(password)
            self.assertIs(result.compliance, compliance)
            self.assertEqual(result.to_dict()['strength'], 'not_assessed')
            self.assertNotIn('Strong', repr(result))
            self.assertNotIn('Strong', json.dumps(result.to_dict()))
            self.assertIn('Strength not assessed', result.message)

    def test_results_and_errors_never_contain_synthetic_secret(self):
        secret = 'SyntheticSecretQ7!z'
        for value in (secret, secret + '\n', secret + '\ud800', secret * 100,
                      secret.encode(), {'secret': secret}):
            result = assess_password(value)
            for rendered in (repr(result), str(result), json.dumps(result.to_dict()),
                             json.dumps(dataclasses.asdict(result)), result.message):
                self.assertNotIn(secret, rendered)
                self.assertNotIn('SyntheticSecret', rendered)
        # Constructors also reject arbitrary input-bearing fields with safe errors.
        for build in (
            lambda: AssessmentResult(secret, ReasonCode.WRONG_TYPE),
            lambda: CriterionResult(Criterion.LENGTH, secret),
            lambda: PolicyResult(PolicyId.LEGACY_ASCII_COMPOSITION, (secret,)),
            lambda: AssessmentResult(AssessmentStatus.POLICY_EVALUATED, ReasonCode.VALID),
        ):
            with self.assertRaises(ValueError) as caught:
                build()
            self.assertNotIn(secret, str(caught.exception))
            self.assertNotIn(secret, repr(caught.exception))
        self.assertEqual(set(assess_password(secret).to_dict()), {
            'status', 'reason', 'message', 'strength', 'compliance', 'policy', 'unicode_classes',
        })

    def test_assessment_performs_no_network_access_or_file_writes(self):
        code = r'''
import sys
from password_checker.core import assess_password
violations = []
def guard(event, args):
    forbidden = event.startswith('socket.') or event in (
        'os.mkdir', 'os.remove', 'os.rename', 'os.rmdir', 'os.truncate',
        'os.chmod', 'os.link', 'os.symlink', 'os.system', 'subprocess.Popen',
    )
    if event == 'open':
        mode, flags = args[1], args[2]
        forbidden |= bool(mode and any(c in mode for c in 'wax+'))
        forbidden |= bool(flags & 3)
    if forbidden:
        violations.append(event)
        raise AssertionError('Forbidden side effect: ' + event)
sys.addaudithook(guard)
for value in ('Abcdef1!', '', None, 'x' * 1025, '漢字😀', '\n', '\ud800'):
    assess_password(value).to_dict()
assert not violations
'''
        completed = subprocess.run(
            [sys.executable, '-B', '-c', code], cwd=ROOT,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, '')
        self.assertEqual(completed.stderr, '')

    def test_compatibility_function_uses_new_contract(self):
        from Password_Strength_Checker import check_password_strength
        self.assertIsInstance(check_password_strength('Abcdef1!'), AssessmentResult)
        self.assertIs(check_password_strength, assess_password)


if __name__ == '__main__':
    unittest.main()
