"""Tkinter presentation; only main() creates a window."""

import tkinter as tk

from .core import assess_password
from .models import ComplianceStatus


def main() -> None:
    window = tk.Tk()
    window.title("Password Policy Checker")

    tk.Label(window, text="Legacy ASCII composition policy (not a strength estimate)").pack(
        padx=20, pady=(15, 0)
    )
    password_entry = tk.Entry(window, show="*", width=50)
    password_entry.pack(pady=20, ipadx=10, ipady=5, fill=tk.X, padx=20)

    output = tk.Label(window, text="Strength not assessed.", wraplength=480, justify=tk.LEFT)

    def evaluate_password() -> None:
        result = assess_password(password_entry.get())
        if result.compliance is ComplianceStatus.NOT_EVALUATED:
            output.config(text=result.message)
        else:
            compliance = (
                "Meets configured requirements"
                if result.compliance is ComplianceStatus.MEETS
                else "Does not meet configured requirements"
            )
            output.config(
                text=f"{compliance} (legacy ASCII composition policy).\nStrength not assessed."
            )

    def clear() -> None:
        password_entry.delete(0, tk.END)
        output.config(text="Strength not assessed.")
        password_entry.focus_set()

    def close() -> None:
        password_entry.delete(0, tk.END)
        window.destroy()

    actions = tk.Frame(window)
    actions.pack(pady=10)
    tk.Button(actions, text="Evaluate", command=evaluate_password, width=20).pack(side=tk.LEFT, padx=5)
    tk.Button(actions, text="Clear", command=clear, width=20).pack(side=tk.LEFT, padx=5)
    output.pack(padx=20, pady=(0, 20))
    window.protocol("WM_DELETE_WINDOW", close)
    password_entry.focus_set()
    window.mainloop()
