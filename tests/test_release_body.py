import importlib.util
import os
import re
import unittest

RACINE = os.path.join(os.path.dirname(__file__), "..")
spec = importlib.util.spec_from_file_location("release_body", os.path.join(RACINE, "tools", "release-body.py"))
release_body = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_body)

with open(os.path.join(RACINE, "docs", "release-notes.md"), encoding="utf-8") as f:
    NOTES = f.read()


class NotesDeVersion(unittest.TestCase):
    def test_chaque_version_a_ses_nouveautes(self):
        versions = re.findall(r"^- \*\*(v[0-9.]+)\*\*", NOTES, re.M)
        self.assertIn("v1.0.0", versions)
        for v in versions:
            with self.subTest(version=v):
                corps = release_body.construire(NOTES, v, "x/y")
                self.assertIn(f"### Nouveautés de la {v}", corps)
                self.assertNotIn("Voir l'historique.", corps)
                self.assertIn(f"IA-Anonymiser-{v}.exe", corps)

    def test_ancienne_version_sans_exe_numerote(self):
        corps = release_body.construire(NOTES, "v1.0.0", "x/y", ["Anonymiseur.exe"])
        self.assertIn("v1.0.0/Anonymiseur.exe", corps)
        self.assertNotIn("IA-Anonymiser-v1.0.0.exe", corps)

    def test_ordre_decroissant(self):
        versions = [tuple(map(int, v[1:].split("."))) for v in re.findall(r"^- \*\*(v[0-9.]+)\*\*", NOTES, re.M)]
        self.assertEqual(versions, sorted(versions, reverse=True))


if __name__ == "__main__":
    unittest.main()
