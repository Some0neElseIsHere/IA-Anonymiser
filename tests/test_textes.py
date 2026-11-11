import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from textes import TEXTES, libelle_jour  # noqa: E402


class Rubriques(unittest.TestCase):
    def test_libelles(self):
        auj = datetime.date(2026, 11, 11)
        cas = [
            (auj, "Aujourd'hui", "Today"),
            (datetime.date(2026, 11, 10), "Hier", "Yesterday"),
            (datetime.date(2026, 11, 9), "9 nov.", "Nov 9"),
            (datetime.date(2026, 1, 1), "1 janv.", "Jan 1"),
            (datetime.date(2025, 12, 24), "24 déc. 2025", "Dec 24, 2025"),
            (datetime.date(2026, 11, 12), "Aujourd'hui", "Today"),  # horloge décalée : pas de date future
        ]
        for jour, fr, en in cas:
            with self.subTest(jour=jour):
                self.assertEqual(libelle_jour(jour, auj, "fr"), fr)
                self.assertEqual(libelle_jour(jour, auj, "en"), en)

    def test_traductions_completes(self):
        self.assertEqual(set(TEXTES["fr"]), set(TEXTES["en"]))


if __name__ == "__main__":
    unittest.main()
