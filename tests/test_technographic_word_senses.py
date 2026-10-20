import unittest

from signalwatch.technographics import extract


class LiteralObjectContextTests(unittest.TestCase):
    def test_explicit_physical_objects_do_not_become_software_assertions(self):
        for text in ("We use stained-glass windows for the lobby.",
                     "We use windows to illuminate the studio.",
                     "Open the windows to let in fresh air.",
                     "We maintain windows and external doors.",
                     "The delicate snowflake melted on a glove.",
                     "Each snowflake falls along a different path.",
                     "We photographed a tiny snowflake that drifted onto the railing."):
            with self.subTest(text=text):
                self.assertEqual(extract(text), [])

    def test_lowercase_brands_and_software_in_physical_settings_are_retained(self):
        cases = [("We run windows containers for the rendering service.", "windows"),
                 ("We use a Snowflake warehouse for accounting.", "snowflake"),
                 ("We use snowflake data pipelines for weather forecasts.", "snowflake"),
                 ("We use Windows to control greenhouse ventilation.", "windows"),
                 ("We use Windows and DOORS for requirements management.", "windows"),
                 ("We maintain Windows Server 2022 in the building.", "windows server")]
        for text, product in cases:
            with self.subTest(text=text):
                self.assertEqual([(row["product"], row["status"]) for row in extract(text)], [(product, "asserted_use")])

    def test_physical_phrase_does_not_hide_separate_software_reference(self):
        rows = extract("We maintain glass windows and deploy Windows Server 2022. We run Snowflake for reporting.")
        self.assertEqual({row["product"] for row in rows}, {"windows server", "snowflake"})
        self.assertNotIn("windows", {row["product"] for row in rows})


if __name__ == "__main__":
    unittest.main()
