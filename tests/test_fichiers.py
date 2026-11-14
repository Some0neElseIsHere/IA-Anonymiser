"""Ouverture d'un fichier de journal : encodages courants sous Windows, fichiers binaires refusés."""
import codecs
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import fichiers  # noqa: E402

TEXTE = "Échec d'ouverture de session : ACME\\jdupont depuis 10.1.2.3 — « été »\nligne 2\n"


class Lecture(unittest.TestCase):
    def ecrire(self, octets, extension=".log"):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=extension)
        f.write(octets)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_encodages(self):
        cas = {
            "UTF-8": TEXTE.encode("utf-8"),
            "UTF-8 BOM": codecs.BOM_UTF8 + TEXTE.encode("utf-8"),
            "UTF-16 (PowerShell >)": codecs.BOM_UTF16_LE + TEXTE.encode("utf-16-le"),
            "UTF-16 BE": codecs.BOM_UTF16_BE + TEXTE.encode("utf-16-be"),
            "UTF-16 sans BOM": TEXTE.encode("utf-16-le"),
            "Windows-1252": TEXTE.replace("—", "-").encode("cp1252"),
            "CRLF": TEXTE.replace("\n", "\r\n").encode("utf-8"),
        }
        for nom, octets in cas.items():
            texte, _ = fichiers.lire(self.ecrire(octets))
            attendu = TEXTE.replace("—", "-") if nom == "Windows-1252" else TEXTE
            self.assertEqual(texte, attendu, nom)

    def test_binaires_refuses(self):
        with self.assertRaises(fichiers.FichierIllisible):
            fichiers.lire(self.ecrire(b"ElfFile\x00\x01\x02\x03" * 50, ".dat"))
        with self.assertRaises(fichiers.FichierIllisible):
            fichiers.lire(self.ecrire(b"texte", ".evtx"))

    def test_plusieurs_fichiers(self):
        self.assertEqual(fichiers.assembler([("C:\\x\\a.log", "un\n"), ("/y/b.txt", "deux")]),
                         "==> a.log <==\nun\n\n==> b.txt <==\ndeux\n")
        self.assertEqual(fichiers.assembler([("a.log", "seul\n")]), "seul\n")


if __name__ == "__main__":
    unittest.main()
