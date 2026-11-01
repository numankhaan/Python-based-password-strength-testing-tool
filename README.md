# Password Policy Checker — Phase 1

This local Python/Tkinter application checks an explicitly named **legacy ASCII
composition policy**. It does not estimate password strength. Every result says
**strength not assessed**. A real estimator is deferred to Phase 2; this version
has no breach service, network requests, dictionaries, or cracking tools.

## Run the GUI

Use Python 3.10 or newer, with Tkinter/Tcl/Tk and a graphical desktop available:

```sh
python3 Password_Strength_Checker.py
```

Tkinter is supplied by some Python distributions. If unavailable, install your
platform's Tk-enabled Python package (commonly `python3-tk` on Linux); it is not a
pip dependency. `python3 -m tkinter` opens a small window to check installation.
The core and tests work without Tkinter or a display. No third-party Python
packages are required.

Enter a password in the masked field and select **Evaluate**. The interface shows
“meets configured requirements” or “does not meet configured requirements” for
valid, nonempty input, alongside “strength not assessed.” Invalid or empty input
receives a safe explanation and no policy evaluation. **Clear** empties the entry
and resets the result; closing the window also empties the entry.

## What the policy means

The preserved `legacy_ascii_composition` policy requires all five criteria:

- At least 8 Python Unicode code points, checked with `len`, not a regex.
- An ASCII uppercase letter (`A-Z`).
- An ASCII lowercase letter (`a-z`).
- An ASCII digit (`0-9`).
- A character outside ASCII letters and digits (`[^A-Za-z0-9]`). This historical
  definition includes spaces, accented/non-Latin letters, emoji, and combining
  marks; it does not mean punctuation alone.

These historical requirements are **not a security recommendation**. Compliance
does not establish resistance to guessing or reuse. There is no score, entropy
calculation, or strength label. For example, `Aa1!` does not meet the requirements
and `Password1!` does; **neither receives a strength assessment**.

## Exact input semantics

The API accepts strings. Non-string values and empty strings return structured
results without policy evaluation. Input is never silently trimmed, normalized,
or truncated. Leading/trailing spaces and all-space input are preserved.

Lengths count **Python Unicode code points**, not bytes or visible characters
(graphemes). For example, a precomposed accented letter and its decomposed
letter-plus-combining-mark form can have different lengths. Non-ASCII letters do
not satisfy ASCII uppercase/lowercase requirements; non-ASCII digits do not
satisfy the ASCII digit requirement. Unicode general categories are reported as
informational presence only: letter, mark, number, punctuation, symbol, separator,
or other. They never award strength points.

The application rejects all Unicode `Cc` control characters (including tabs and
NUL), all `Cs` surrogate code points (including explicit surrogate pairs), and
line breaks: LF, CR, VT, FF, U+001C–U+001E, NEL, U+2028 and U+2029. Other categories,
including `Cf` format characters such as zero-width joiners, are accepted exactly
as entered. A real emoji represented by its Unicode scalar value is accepted.

The provisional cap is **1024 code points**, an application processing limit,
not a password-security rule. Longer input is explicitly rejected before any
policy evaluation; a truncated prefix is never evaluated. Validation priority is
wrong type, empty, over limit, line break, surrogate, then other control.

## Core API and compatibility

```python
from password_checker.core import assess_password

result = assess_password("Abcdef1!")  # Synthetic example only.
assert result.compliance.value == "meets_configured_requirements"
assert result.strength.value == "not_assessed"
safe_data = result.to_dict()  # JSON-compatible, contains no password.
```

`assess_password(value)` returns a frozen `AssessmentResult`, with `status`,
`reason`, optional `policy`, and informational `unicode_classes`. Properties
provide `compliance`, `strength`, and a fixed safe `message`. `to_dict()` serializes
only these allowlisted values. Status is `policy_evaluated`, `empty_input`, or
`invalid_input`; reason codes are `valid`, `empty_input`, `invalid_type`,
`input_limit_exceeded`, `line_break`, `isolated_surrogate`, and `control_character`.
Policy results contain the policy identifier and five named Boolean criteria,
never a numeric strength score. Invalid/empty results have no policy or category
information and have compliance `not_evaluated`.

The historical `Password_Strength_Checker.check_password_strength` name remains
an alias to this API, **but its return contract changed from a label string to
`AssessmentResult`**. Callers must use the result fields. Importing the launcher
or core does not import Tkinter, create a window, or start an event loop. The
launcher starts Tkinter only when run as a script.

## Privacy and limits

Assessment runs locally with no network access, logging, or persistence. Results,
representations, serialization, and validation messages contain only allowlisted
metadata: no passwords, contextual input values, matched substrings, or hashes.
Avoid printing or storing the input in calling code.

The GUI holds the entered text until Clear or close; Evaluate obtains a temporary
Python string. There is no password history or retained password in results.
Clearing Tk widgets or releasing Python references **does not securely wipe
memory**. Tk/Python or the operating system may retain memory copies. Masking
prevents ordinary on-screen display; it is not memory protection.

## Validation

From the repository root:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q Password_Strength_Checker.py password_checker tests
```

Tests use synthetic inputs, check headless imports, legacy policy boundaries,
Unicode and invalid-input behavior, safe results/errors, absence of assessment
network/file-write activity, and GUI callbacks with a fake Tk implementation.
The callback test does not replace a real GUI smoke test on a graphical desktop.

## License

This project is licensed under the MIT License. See [MIT License](MIT%20License).
