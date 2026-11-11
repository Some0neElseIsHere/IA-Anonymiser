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

    def test_premier_lancement(self):
        with tempfile.TemporaryDirectory() as d:
            o = stockage.Options(d)
            self.assertTrue(o.premier_lancement)   # écran d'accueil affiché
            o.sauver()
            self.assertFalse(stockage.Options(d).premier_lancement)  # plus jamais ensuite

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

    def test_nouveaux_types_actives(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            # Options enregistrées par la v1.3 : 8 types connus, le téléphone désactivé
            with open(os.path.join(d, "options.json"), "w", encoding="utf-8") as f:
                json.dump({"types": ["EMAIL", "IBAN", "CARTE", "SECU", "IP", "MAC", "FQDN"]}, f)
            o = stockage.Options(d)
            self.assertNotIn("TEL", o.types)          # choix de l'utilisateur conservé
            for nouveau in ("SECRET", "COMPTE", "DN", "SID"):
                self.assertIn(nouveau, o.types)        # nouveaux types activés
            o.types.discard("SID")
            o.motifs = stockage.motifs_valides(["PC-\\d{4}", "PC-(", "", {"titre": "Tickets", "motif": "INC-\\d+"}])
            o.sauver()
            o2 = stockage.Options(d)
            self.assertNotIn("SID", o2.types)         # désactivé après coup : reste désactivé
            self.assertEqual(o2.motifs, [{"titre": "", "motif": "PC-\\d{4}"},
                                         {"titre": "Tickets", "motif": "INC-\\d+"}])


if __name__ == "__main__":
    unittest.main()
