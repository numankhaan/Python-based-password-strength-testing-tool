"""Exercise GUI callbacks headlessly; this does not replace a real Tk smoke test."""

import importlib.util
from pathlib import Path
import types
import unittest
from unittest.mock import patch


class Widget:
    def __init__(self, parent=None, **options):
        self.options = options
        self.value = ''
        self.packs = []
        self.deletions = 0
        self.destroyed = False
        self.protocols = {}

    def pack(self, **options):
        self.packs.append(options)

    def config(self, **options):
        self.options.update(options)

    def get(self):
        return self.value

    def delete(self, start, end):
        self.value = ''
        self.deletions += 1

    def focus_set(self):
        pass

    def title(self, title):
        self.title_text = title

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def destroy(self):
        self.destroyed = True


class GuiTests(unittest.TestCase):
    def test_mask_evaluate_clear_and_close(self):
        widgets = []
        fake_tk = types.ModuleType('tkinter')

        def create(**options):
            widget = Widget(**options)
            widgets.append(widget)
            return widget

        for kind in ('Tk', 'Entry', 'Label', 'Button', 'Frame'):
            setattr(fake_tk, kind, lambda parent=None, **options: create(parent=parent, **options))
        for constant in ('X', 'LEFT', 'END'):
            setattr(fake_tk, constant, constant)

        def interact():
            entry = next(widget for widget in widgets if 'show' in widget.options)
            output = next(widget for widget in widgets if 'wraplength' in widget.options)
            buttons = {widget.options['text']: widget.options['command']
                       for widget in widgets if 'command' in widget.options}
            self.assertEqual(entry.options['show'], '*')
            self.assertEqual(len(entry.packs), 1)
            for value, expected in [
                ('Aa1!', 'Does not meet configured requirements'),
                ('Password1!', 'Meets configured requirements'),
                ('SyntheticSecretQ7!\n', 'Line breaks are not accepted'),
                ('', 'Enter a password'),
                ('x' * 1025, 'processing limit'),
            ]:
                entry.value = value
                buttons['Evaluate']()
                self.assertIn(expected, output.options['text'])
                self.assertIn('Strength not assessed', output.options['text'])
                self.assertNotIn('SyntheticSecret', output.options['text'])
            buttons['Clear']()
            self.assertEqual(entry.value, '')
            self.assertEqual(output.options['text'], 'Strength not assessed.')
            entry.value = 'SyntheticSecretQ7!'
            widgets[0].protocols['WM_DELETE_WINDOW']()
            self.assertEqual(entry.value, '')
            self.assertEqual(entry.deletions, 2)
            self.assertTrue(widgets[0].destroyed)

        def mainloop(window):
            interact()

        with patch.object(Widget, 'mainloop', mainloop, create=True):
            with patch.dict('sys.modules', {'tkinter': fake_tk}):
                path = Path(__file__).resolve().parents[1] / 'password_checker' / 'gui.py'
                spec = importlib.util.spec_from_file_location('password_checker._gui_test', path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.assertEqual(widgets, [])  # GUI import alone creates no window.
                module.main()


if __name__ == '__main__':
    unittest.main()
