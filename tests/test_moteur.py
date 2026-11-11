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

    def test_meme_donnee_ecrite_autrement(self):
        a = Anonymiseur()
        a.anonymiser("+33 6 12 34 56 78, FR76 3000 6000 0112 3456 7890 189, 3C:52:82:1A:9F:07", [])
        a.valider()
        r = a.anonymiser("06.12.34.56.78 / 0033612345678 / +33 (0)6 12 34 56 78 / FR7630006000011234567890189 / "
                         "3c-52-82-1a-9f-07", [])
        self.assertEqual(r.texte, "[TEL_1] / [TEL_1] / [TEL_1] / [IBAN_1] / [MAC_1]")

    def test_numeros_differents(self):
        _, r = anon("06 12 34 56 78 et 06 12 34 56 79, +44 20 7946 0958")
        self.assertEqual(r.texte, "[TEL_1] et [TEL_2], [TEL_3]")

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


class Langues(unittest.TestCase):
    def test_jetons_en_anglais(self):
        a = Anonymiseur("en")
        r = a.anonymiser("John Smith, 06 12 34 56 78, 4111 1111 1111 1111", ["John Smith"])
        self.assertEqual(r.texte, "[NAME_1], [PHONE_1], [CARD_1]")
        self.assertEqual(a.restaurer("Hi [name_1]").texte, "Hi John Smith")

    def test_changement_de_langue_en_cours(self):
        a = Anonymiseur("fr")
        a.anonymiser("Jean Dupont", ["Jean Dupont"])
        a.valider()
        a.langue = "en"
        r = a.anonymiser("Jean Dupont et Paul Martin", ["Jean Dupont", "Paul Martin"])
        self.assertEqual(r.texte, "[NOM_1] et [NAME_2]")
        self.assertEqual(a.restaurer("[NOM_1] [NAME_2]").texte, "Jean Dupont Paul Martin")


class Etat(unittest.TestCase):
    def test_sauvegarde_et_reprise(self):
        a = Anonymiseur()
        a.anonymiser("a@b.fr et 06 12 34 56 78", [])
        a.valider()
        a.exclus.add("[TEL_1]")
        b = Anonymiseur()
        b.charger_etat(a.etat())
        self.assertEqual(b.restaurer("[EMAIL_1]").texte, "a@b.fr")
        self.assertEqual(b.anonymiser("x@y.fr, 06 12 34 56 78", []).texte, "[EMAIL_2], 06 12 34 56 78")
        self.assertEqual(b.jetons(), ["[EMAIL_1]", "[TEL_1]", "[EMAIL_2]"])


if __name__ == "__main__":
    unittest.main()


class JetonsPersonnalises(unittest.TestCase):
    def test_jeton_personnalise_des_le_depart(self):
        a = Anonymiseur()
        a.etiquettes = {"acme industries": "ENTREPRISE"}
        r = a.anonymiser("Acme Industries et Jean Dupont", ["Acme Industries", "Jean Dupont"])
        self.assertEqual(r.texte, "[ENTREPRISE] et [NOM_1]")
        self.assertEqual(a.renommages(), {})  # rien à annoncer : l'IA n'a jamais vu d'autre jeton

    def test_renommage_annonce_une_fois(self):
        a = Anonymiseur()
        a.anonymiser("Acme Industries", ["Acme Industries"])
        a.valider()                                    # envoyé sous [NOM_1]
        a.etiquettes = {"acme industries": "ENTREPRISE"}
        r = a.anonymiser("Acme Industries", ["Acme Industries"])
        self.assertEqual(r.texte, "[ENTREPRISE]")
        self.assertEqual(a.renommages(), {"[NOM_1]": "[ENTREPRISE]"})
        a.valider()
        a.renommages_annonces()                        # annoncé à la copie
        a.anonymiser("Acme Industries", ["Acme Industries"])
        self.assertEqual(a.renommages(), {})

    def test_ancien_et_nouveau_jeton_restaures(self):
        a = Anonymiseur()
        a.anonymiser("Acme Industries", ["Acme Industries"])
        a.valider()
        a.etiquettes = {"acme industries": "CLIENT_PRINCIPAL"}
        a.anonymiser("Acme Industries", ["Acme Industries"])
        a.valider()
        r = a.restaurer("[NOM_1], [CLIENT_PRINCIPAL], [client_principal], \\[CLIENT\\_PRINCIPAL\\], [CLIENT]")
        self.assertEqual(r.texte, "Acme Industries, Acme Industries, Acme Industries, Acme Industries, [CLIENT]")

    def test_renommage_conserve_au_redemarrage(self):
        a = Anonymiseur()
        a.anonymiser("Acme Industries", ["Acme Industries"])
        a.valider()
        a.etiquettes = {"acme industries": "ENTREPRISE"}
        a.anonymiser("Acme Industries", ["Acme Industries"])
        a.valider()                                    # copié sans annonce (copie manuelle)
        b = Anonymiseur()
        b.charger_etat(a.etat())
        self.assertEqual(b.renommages(), {"[NOM_1]": "[ENTREPRISE]"})   # toujours à annoncer
        b.etiquettes = {}                              # jeton personnalisé retiré ensuite
        self.assertEqual(b.anonymiser("Acme Industries", ["Acme Industries"]).texte, "[ENTREPRISE]")

    def test_etiquettes(self):
        from moteur import etiquette_reservee, normaliser_etiquette
        self.assertEqual(normaliser_etiquette(" client principal "), "CLIENT_PRINCIPAL")
        self.assertEqual(normaliser_etiquette("[Société]"), "SOCIETE")
        self.assertTrue(etiquette_reservee("NOM_3"))
        self.assertTrue(etiquette_reservee("NAME_12"))
        self.assertFalse(etiquette_reservee("ENTREPRISE"))
        self.assertFalse(etiquette_reservee("NOM"))


class Performance(unittest.TestCase):
    def test_gros_log(self):
        """Un log de 3 000 lignes doit rester rapide, même avec des centaines de valeurs connues."""
        import time
        lignes = [f"2026-11-10 12:{i % 60:02d}:01 srv{i % 40}.acme.local [10.0.{i % 250}.{i % 200}] GET "
                  f"/api/v1/items?id={i} 200 user{i % 50}@acme.fr user=jdoe{i % 30}" for i in range(3000)]
        log = "\n".join(lignes)
        a = Anonymiseur()
        a.anonymiser(log, ["Acme SAS"])
        a.valider()
        debut = time.perf_counter()
        r = a.anonymiser(log, ["Acme SAS"])
        self.assertLess(time.perf_counter() - debut, 2.0)  # environ 0,4 s ; 3,4 s avant la correction
        self.assertEqual(a.restaurer(r.texte).texte, log)
