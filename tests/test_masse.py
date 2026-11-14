"""Tests de masse : des centaines de logs générés, avec données sensibles et pièges connus."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from generateur import Univers, document  # noqa: E402
from moteur import JETON_RE, jeton_canonique, Anonymiseur  # noqa: E402

NB_DOCUMENTS = 400


def anonymiser_tout(graine, langue="fr"):
    u = Univers(graine)
    a = Anonymiseur(langue)
    resultats = []
    for n in range(NB_DOCUMENTS):
        texte, sensibles, pieges = document(u, n)
        r = a.anonymiser(texte, u.termes(), None, u.motifs())
        a.valider()
        resultats.append((n, texte, r, sensibles, pieges))
    return u, a, resultats


class Masse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.u, cls.a, cls.resultats = anonymiser_tout(2026)

    def test_aucune_fuite(self):
        fuites = []
        for n, texte, r, sensibles, _ in self.resultats:
            for valeur in sensibles:
                if valeur in r.texte:
                    fuites.append((n, valeur))
        self.assertEqual(fuites[:20], [], f"{len(fuites)} fuite(s)")

    def test_pieges_intacts(self):
        abimes = []
        for n, texte, r, _, pieges in self.resultats:
            for valeur in pieges:
                if valeur not in r.texte:
                    abimes.append((n, valeur))
        self.assertEqual(abimes[:20], [], f"{len(abimes)} piège(s) masqué(s) à tort")

    def test_aller_retour_exact(self):
        for n, texte, r, _, _ in self.resultats:
            with self.subTest(document=n):
                self.assertEqual(self.a.restaurer(r.texte).texte, texte)

    def test_jetons_coherents(self):
        """Une même valeur garde le même jeton dans toute la conversation."""
        vus = {}
        for _, _, r, _, _ in self.resultats:
            for jeton in r.compte:
                type_, valeur = self.a.info(jeton)
                cle = (type_, valeur.casefold() if type_ != "SECRET" else valeur)
                vus.setdefault(cle, set()).add(jeton)
        multiples = {c: j for c, j in vus.items() if len(j) > 1}
        self.assertEqual(multiples, {})

    def test_jetons_tous_restaurables(self):
        for n, _, r, _, _ in self.resultats:
            for m in JETON_RE.finditer(r.texte):
                with self.subTest(document=n, jeton=m.group(0)):
                    self.assertIsNotNone(self.a.info(jeton_canonique(m.group(1), m.group(2))))

    def test_reponse_ia_simulee(self):
        """Une « réponse d'IA » qui reprend des jetons en les déformant un peu est bien restaurée."""
        jetons = list(self.a.valide)[:40]
        reponse = " ".join(
            (j.lower() if k % 3 == 0 else j.replace("_", "\\_").replace("[", "\\[").replace("]", "\\]") if k % 3 == 1
             else j.replace("_", " ")) for k, j in enumerate(jetons))
        restauree = self.a.restaurer(reponse)
        self.assertEqual(restauree.inconnus, [])
        self.assertEqual(sum(restauree.compte.values()), len(jetons))

    def test_etat_sauvegarde(self):
        b = Anonymiseur()
        b.charger_etat(self.a.etat())
        for n, texte, r, _, _ in self.resultats[:50]:
            self.assertEqual(b.restaurer(r.texte).texte, texte)
            # Reprise : même résultat qu'avec la conversation d'origine aujourd'hui (elle a appris des valeurs
            # depuis, et masque donc parfois plus que lors du premier passage)
            attendu = self.a.anonymiser(texte, self.u.termes(), None, self.u.motifs()).texte
            self.assertEqual(b.anonymiser(texte, self.u.termes(), None, self.u.motifs()).texte, attendu)

    def test_anglais(self):
        u, a, resultats = anonymiser_tout(7, "en")
        for n, texte, r, sensibles, _ in resultats[:120]:
            for valeur in sensibles:
                self.assertNotIn(valeur, r.texte, f"document {n}")
            self.assertEqual(a.restaurer(r.texte).texte, texte)
            self.assertNotRegex(r.texte, r"\[(NOM|TEL|CARTE|COMPTE)_\d+\]")

    def test_jeton_renomme_en_cours(self):
        """Changer le jeton d'une entreprise en pleine conversation : annonce, cohérence, restauration."""
        u = Univers(99)
        a = Anonymiseur()
        entreprise = u.entreprises[0]
        textes = []
        for n in range(30):
            if n == 15:
                a.etiquettes = {entreprise.casefold(): "ENTREPRISE"}
            texte = document(u, n)[0] + f"\nContrat avec {entreprise}."
            r = a.anonymiser(texte, u.termes(), None, u.motifs())
            if n == 15:
                self.assertTrue(any(nouveau == "[ENTREPRISE]" for nouveau in a.renommages().values()))
            a.valider()
            a.renommages_annonces()
            textes.append((texte, r.texte))
            if n >= 15:
                self.assertIn("[ENTREPRISE]", r.texte)
                self.assertNotIn(entreprise, r.texte)
        for texte, envoye in textes:
            self.assertEqual(a.restaurer(envoye).texte, texte)


if __name__ == "__main__":
    unittest.main()
