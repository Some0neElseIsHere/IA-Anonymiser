import html
import os
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import rapport  # noqa: E402
from moteur import TYPES_AUTO, Anonymiseur  # noqa: E402
from textes import Traducteur  # noqa: E402

LOG = (
    "Jean Dupont (Acme SAS) jean.dupont@acme.fr 06 12 34 56 78, FR76 3000 6000 0112 3456 7890 189, "
    "carte 4111 1111 1111 1111, 10.20.30.41, srv-paie01.acme.local, password=Paie2026!, "
    "ACME\\jdupont, CN=Jean Dupont,OU=Compta,DC=acme,DC=local, S-1-5-21-1-2-3-1013, PC-0815"
)
VRAIES_VALEURS = ["Dupont", "Acme SAS", "jean.dupont@acme.fr", "06 12 34 56 78", "FR76 3000",
                  "4111 1111", "10.20.30.41", "srv-paie01", "Paie2026!", "jdupont", "OU=Compta",
                  "S-1-5-21-1-2-3-1013", "PC-0815"]


def conversation(nom="Incident <paie> & co"):
    moteur = Anonymiseur("fr")
    res = moteur.anonymiser(LOG, ["Jean Dupont", "Acme SAS"], None, [r"PC-\d{4}"])
    moteur.valider()
    envoi = "Consigne : garde les jetons.\n\n" + res.texte
    return SimpleNamespace(nom=nom, moteur=moteur, termes=["Jean Dupont"], cree=time.time() - 3600,
                           activite=time.time(), envois=[{"date": time.time(), "texte": envoi}]), envoi


def generer(conv, langue="fr"):
    t = Traducteur(langue)
    options = SimpleNamespace(types=set(TYPES_AUTO), permanents=["Acme SAS"], motifs=[r"PC-\d{4}"], consigne=True)
    return rapport.generer(conv, options, t, "v1.6.0", lambda type_, valeur: t(f"type_{type_}"))


class Rapport(unittest.TestCase):
    def test_valeurs_d_origine_presentes(self):
        for langue in ("fr", "en"):
            conv, _ = conversation()
            page = html.unescape(generer(conv, langue))
            for valeur in VRAIES_VALEURS:
                with self.subTest(langue=langue, valeur=valeur):
                    self.assertIn(valeur, page)

    def test_textes_envoyes_restent_anonymises(self):
        conv, envoi = conversation()
        page = html.unescape(generer(conv))
        bloc = page[page.index(envoi[:20]):]
        for valeur in ("Paie2026!", "jean.dupont@acme.fr", "10.20.30.41"):
            self.assertNotIn(valeur, bloc[:len(envoi)])

    def test_utilisateur_et_avertissement(self):
        conv, _ = conversation()
        t = Traducteur("fr")
        options = SimpleNamespace(types=set(TYPES_AUTO), permanents=[], motifs=[], consigne=True)
        page = html.unescape(rapport.generer(conv, options, t, "v1.6.1", lambda a, b: a,
                                             utilisateur="ACME\\mlefevre"))
        self.assertIn("par ACME\\mlefevre, avec IA-Anonymiser v1.6.1", page)
        self.assertIn("Document confidentiel", page)
        self.assertNotIn("Résumé", page)

    def test_envoi_en_clair_signale(self):
        """Une valeur partie en clair dans un envoi (ancienne version, terme ajouté trop tard) est signalée."""
        conv, envoi = conversation()
        conv.envois.insert(0, {"date": time.time() - 60, "texte": "Login for 'jdupont' from 10.20.30.41"})
        page = html.unescape(generer(conv))
        self.assertIn("envoyé en clair (envoi 1)", page)
        self.assertIn("<tr><th>Éléments envoyés en clair par erreur</th><td class=\"alerte\">1</td></tr>", page)

    def test_aucune_fuite(self):
        conv, _ = conversation()
        page = html.unescape(generer(conv))
        self.assertNotIn("envoyé en clair (", page)
        self.assertIn("<tr><th>Éléments envoyés en clair par erreur</th><td>0</td></tr>", page)

    def test_valeur_echappee(self):
        conv, _ = conversation()
        conv.moteur.valide["[NOM_9]"] = ("NOM", "<script>alert(1)</script>")
        page = generer(conv)
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertEqual(page.count("<script>"), 1)  # seul le script de tri du rapport

    def test_contenu(self):
        conv, envoi = conversation()
        page = generer(conv)
        self.assertIn("[NOM_1]", page)
        self.assertIn("[SECRET_1]", page)
        self.assertIn(rapport.empreinte(envoi), page)
        self.assertIn("Incident &lt;paie&gt; &amp; co", page)  # nom échappé
        self.assertNotIn("<paie>", page)

    def test_element_laisse_en_clair(self):
        conv, _ = conversation()
        conv.moteur.exclus.add("[IP_privée_1]")
        page = generer(conv)
        self.assertIn("laissé en clair par l'utilisateur", html.unescape(page))

    def test_sans_envoi_ni_date_de_creation(self):
        conv, _ = conversation()
        conv.envois, conv.cree = [], None
        page = generer(conv)
        self.assertIn("Aucun envoi enregistré", page)
        self.assertIn("inconnue", page)

    def test_synthese(self):
        conv, _ = conversation()
        page = html.unescape(generer(conv))
        self.assertIn("<h2>Synthèse</h2>", page)
        self.assertIn('<div class="n">13</div><div class="l">éléments masqués</div>', page)
        self.assertIn("E-mail : 1", page)
        self.assertIn("<tr><th>Domaines publics connus laissés lisibles</th><td>non</td></tr>", page)

    def test_premier_envoi_et_nombre(self):
        conv, envoi = conversation()
        conv.envois.append({"date": time.time() + 60, "texte": "Encore [IBAN_1] et [NOM_1]"})
        page = html.unescape(generer(conv))
        ligne = page[page.index("<code>[IBAN_1]</code>"):].split("</tr>")[0]
        self.assertIn('<td data-tri="1">1</td><td>2</td>', ligne)
        ligne = page[page.index("<code>[SID_1]</code>"):].split("</tr>")[0]
        self.assertIn('<td data-tri="1">1</td><td>1</td>', ligne)

    def test_renommage_explique(self):
        moteur = Anonymiseur("fr")
        moteur.anonymiser("Acme SAS signe.", ["Acme SAS"], None, [])
        moteur.valider()
        envoi1 = "[NOM_1] signe."
        moteur.etiquettes = {"acme sas": "ENTREPRISE"}
        moteur.anonymiser("Acme SAS paie.", ["Acme SAS"], None, [])
        moteur.valider()
        conv = SimpleNamespace(nom="x", moteur=moteur, termes=[], cree=None, activite=time.time(),
                               envois=[{"date": 1, "texte": envoi1}, {"date": 2, "texte": "[ENTREPRISE] paie."}])
        page = html.unescape(generer(conv))
        self.assertIn("renommé en [ENTREPRISE] à l'envoi 2", page)
        self.assertIn('<div class="n">1</div><div class="l">éléments masqués</div>', page)

    def test_fuite_surlignee_dans_le_texte(self):
        conv, _ = conversation()
        conv.envois.insert(0, {"date": time.time() - 60, "texte": "Login for 'jdupont' from 10.20.30.41"})
        page = generer(conv)
        self.assertIn('<span class="fuite-texte">10.20.30.41</span>', page)
        self.assertIn('<details class="avec-fuite" open>', page)
        self.assertIn('<span class="jeton">[SECRET_1]</span>', page)

    def test_consigne_et_annonce_ne_comptent_pas(self):
        from textes import CONSIGNES
        moteur = Anonymiseur("fr")
        moteur.anonymiser("Acme SAS et jean@acme.fr", ["Acme SAS"], None, [])
        moteur.valider()
        envoi1 = CONSIGNES["fr"].rstrip() + "\n\n[NOM_1] et [EMAIL_1]"
        envoi2 = (CONSIGNES["fr"].rstrip() + "\n\nChangement de jeton : [NOM_1] s'appelle désormais [X]. "
                  "C'est le même élément.\n\nRien d'autre.")
        conv = SimpleNamespace(nom="x", moteur=moteur, termes=[], cree=None, activite=time.time(),
                               envois=[{"date": 1, "texte": envoi1}, {"date": 2, "texte": envoi2}])
        page = html.unescape(generer(conv))
        for jeton in ("[NOM_1]", "[EMAIL_1]"):
            ligne = page[page.index(f"<code>{jeton}</code>"):].split("</tr>")[0]
            self.assertIn('<td data-tri="1">1</td><td>1</td>', ligne)
        self.assertRegex(page, r"Envoi 2, le [\d-]+ [\d:]+ · 0 jeton\(s\)")

    def test_barre_oblique_hors_du_jeton(self):
        self.assertEqual(rapport._texte_envoi("C:\\Users\\[COMPTE_1]\\x", [], ["[COMPTE_1]"]),
                         'C:\\Users\\<span class="jeton">[COMPTE_1]</span>\\x')


    def test_type_decoche_n_est_pas_une_fuite(self):
        # IBAN masqué au premier envoi, puis case IBAN décochée : le 2e envoi le contient en clair, par choix
        conv, envoi = conversation()
        iban = next(v for ty, v in conv.moteur.valide.values() if ty == "IBAN")
        conv.envois.append({"date": time.time(), "texte": "Compte " + iban,
                            "types": sorted(set(TYPES_AUTO) - {"IBAN"}), "publics": False})
        page = generer(conv)
        self.assertIn("type décoché dans la conversation (envoi 2)", page)
        self.assertNotIn("envoyé en clair (envoi", page)
        # Le même envoi avec la case cochée est bien une fuite
        conv.envois[-1]["types"] = sorted(TYPES_AUTO)
        self.assertIn("envoyé en clair (envoi 2)", generer(conv))

    def test_ancien_envoi_suit_les_reglages_de_la_conversation(self):
        conv, envoi = conversation()
        iban = next(v for ty, v in conv.moteur.valide.values() if ty == "IBAN")
        conv.envois.append({"date": time.time(), "texte": "Compte " + iban})
        conv.types = set(TYPES_AUTO) - {"IBAN"}
        self.assertIn("type décoché dans la conversation (envoi 2)", generer(conv))

if __name__ == "__main__":
    unittest.main()
