import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import stockage  # noqa: E402


class Stockage(unittest.TestCase):
    def test_conversations_aller_retour(self):
        with tempfile.TemporaryDirectory() as d:
            donnees = {"conversations": [{"nom": "Test é", "valide": {"[NOM_1]": ["NOM", "Jean Dupont"]}}]}
            stockage.sauver_conversations(donnees, d)
            brut = open(stockage.chemin_conversations(d), "rb").read()
            if sys.platform == "win32":
                self.assertTrue(brut.startswith(stockage.ENTETE_DPAPI))
                self.assertNotIn(b"Dupont", brut)  # chiffré par DPAPI
            self.assertEqual(stockage.charger_conversations(d), donnees)

    def test_pas_de_fichier(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(stockage.charger_conversations(d))

    def test_options_reprise_v11(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "termes.txt"), "w", encoding="utf-8") as f:
                f.write("Acme SAS\nacme sas\nJean Dupont\n")
            o = stockage.Options(d)
            self.assertEqual(o.permanents, ["Acme SAS", "Jean Dupont"])
            o.theme, o.langue, o.consigne_texte = "sombre", "en", "Keep tokens."
            o.sauver()
            o2 = stockage.Options(d)
            self.assertEqual((o2.theme, o2.langue, o2.consigne_texte), ("sombre", "en", "Keep tokens."))


if __name__ == "__main__":
    unittest.main()
