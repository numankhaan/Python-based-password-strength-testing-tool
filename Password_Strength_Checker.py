"""Compatibility launcher and function alias; importing this module is headless."""

from password_checker.core import assess_password

# The historical name now returns an AssessmentResult, never a strength label.
check_password_strength = assess_password


if __name__ == "__main__":
    from password_checker.gui import main

    main()
