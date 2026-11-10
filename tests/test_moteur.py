import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from moteur import Anonymiseur  # noqa: E402


def anon(texte, termes=()):
    a = Anonymiseur()
    return a, a.anonymiser(texte, termes)


class Detection(unittest.TestCase):
    def test_email(self):
        _, r = anon("Écrire à jean.dupont@exemple.fr.")
        self.assertEqual(r.texte, "Écrire à [EMAIL_1].")

    def test_telephones(self):
        _, r = anon("06 12 34 56 78, 01.23.45.67.89, +33 6 12 34 56 79, 0033612345670")
        self.assertEqual(r.texte, "[TEL_1], [TEL_2], [TEL_3], [TEL_4]")

    def test_iban_carte_ip(self):
        _, r = anon("FR76 3000 6000 0112 3456 7890 189 / 4111 1111 1111 1111 / 192.168.1.10.")
        self.assertEqual(r.texte, "[IBAN_1] / [CARTE_1] / [IP_1].")

    def test_securite_sociale(self):
        _, r = anon("NIR : 1 85 05 78 006 084 36")
        self.assertEqual(r.texte, "NIR : [SECU_1]")

    def test_termes_insensibles_casse_et_espaces(self):
        _, r = anon("Jean Dupont, JEAN  DUPONT et jean\ndupont.", ["Jean Dupont"])
        self.assertEqual(r.texte, "[NOM_1], [NOM_1] et [NOM_1].")

    def test_terme_pas_dans_un_mot(self):
        _, r = anon("Acme et Acmeo", ["Acme"])
        self.assertEqual(r.texte, "[NOM_1] et Acmeo")

    def test_email_prioritaire_sur_terme(self):
        _, r = anon("contact@acme.fr", ["acme"])
        self.assertEqual(r.texte, "[EMAIL_1]")

    def test_fqdn(self):
        _, r = anon("Serveurs srv-paie01.acme.local et intranet.acme.fr.")
        self.assertEqual(r.texte, "Serveurs [FQDN_1] et [FQDN_2].")

    def test_fqdn_pas_les_fichiers(self):
        _, r = anon("Voir rapport.pdf et config.yml, version 2.4.1")
        self.assertEqual(r.texte, "Voir rapport.pdf et config.yml, version 2.4.1")

    def test_fqdn_dans_url(self):
        _, r = anon("https://intranet.acme.fr/rh")
        self.assertEqual(r.texte, "https://[FQDN_1]/rh")

    def test_mac(self):
        _, r = anon("MAC 00:1A:2B:3C:4D:5E ou 00-1a-2b-3c-4d-5f")
        self.assertEqual(r.texte, "MAC [MAC_1] ou [MAC_2]")

    def test_types_choisis(self):
        a = Anonymiseur()
        r = a.anonymiser("a@b.fr, 10.0.0.1, srv.acme.fr, Acme", ["Acme"], types={"IP"})
        self.assertEqual(r.texte, "a@b.fr, [IP_1], srv.[NOM_1].fr, [NOM_1]")

    def test_texte_sans_donnee(self):
        _, r = anon("Bonjour, version 2.0 du 12/03/2024.")
        self.assertEqual(r.texte, "Bonjour, version 2.0 du 12/03/2024.")


class Jetons(unittest.TestCase):
    def test_meme_valeur_meme_jeton(self):
        a = Anonymiseur()
        a.anonymiser("a@b.fr", [])
        a.valider()
        r = a.anonymiser("x@y.fr puis a@b.fr", [])
        self.assertEqual(r.texte, "[EMAIL_2] puis [EMAIL_1]")

    def test_frappe_progressive_ne_cree_pas_de_jetons(self):
        a = Anonymiseur()
        a.anonymiser("jean@ex.f", [])
        r = a.anonymiser("jean@ex.fr", [])
        self.assertEqual(r.texte, "[EMAIL_1]")

    def test_exclusion(self):
        a = Anonymiseur()
        r = a.anonymiser("a@b.fr et 06 12 34 56 78", [])
        a.exclus.add("[EMAIL_1]")
        r = a.anonymiser("a@b.fr et 06 12 34 56 78", [])
        self.assertEqual(r.texte, "a@b.fr et [TEL_1]")
        self.assertEqual(r.ignores["[EMAIL_1]"], 1)


class Restauration(unittest.TestCase):
    def setUp(self):
        self.a = Anonymiseur()
        self.a.anonymiser("Jean Dupont, jean@ex.fr", ["Jean Dupont"])
        self.a.valider()

    def test_simple(self):
        self.assertEqual(self.a.restaurer("Bonjour [NOM_1] ([EMAIL_1])").texte,
                         "Bonjour Jean Dupont (jean@ex.fr)")

    def test_variantes(self):
        r = self.a.restaurer("[nom_1] [ NOM_1 ] [NOM 1] \\[NOM\\_1\\] **[NOM_1]**")
        self.assertEqual(r.texte, "Jean Dupont Jean Dupont Jean Dupont Jean Dupont **Jean Dupont**")

    def test_jeton_inconnu(self):
        r = self.a.restaurer("[NOM_9]")
        self.assertEqual(r.texte, "[NOM_9]")
        self.assertEqual(len(r.inconnus), 1)

    def test_aller_retour(self):
        texte = "M. Jean Dupont (06 12 34 56 78, jean@ex.fr) a payé avec FR76 3000 6000 0112 3456 7890 189."
        a = Anonymiseur()
        r = a.anonymiser(texte, ["Jean Dupont"])
        self.assertNotIn("Dupont", r.texte)
        self.assertEqual(a.restaurer(r.texte).texte, texte)


if __name__ == "__main__":
    unittest.main()
