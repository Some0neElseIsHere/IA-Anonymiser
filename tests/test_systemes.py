"""Batterie Windows / Linux : journaux générés dont on connaît toutes les valeurs sensibles.

Événements Security et Sysmon tels qu'affichés, ipconfig /all, Get-ADUser, net user, transcripts PowerShell,
auth.log, journalctl, auditd, journaux d'accès web, /etc/passwd. Les noms complets sont donnés comme termes ;
comptes, machines, domaines, adresses et mots de passe doivent être trouvés seuls.
"""
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from generateur_systemes import PIEGES, Univers, document  # noqa: E402
from moteur import TYPES_AUTO, Anonymiseur  # noqa: E402

N = 400


class Systemes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cas = []
        debut = time.perf_counter()
        for graine in range(N):
            u = Univers(graine)
            texte = document(u, 5)
            a = Anonymiseur("fr")
            r = a.anonymiser(texte, u.termes, TYPES_AUTO, [])
            a.valider()
            cls.cas.append((u, texte, r.texte, a))
        cls.duree = time.perf_counter() - debut

    def test_aucune_fuite(self):
        fuites = []
        for u, _, sortie, _ in self.cas:
            for v in u.sensibles:
                if re.search(r"(?<![\w-])" + re.escape(v) + r"(?![\w-])", sortie, re.IGNORECASE):
                    fuites.append(v)
        self.assertEqual(fuites[:20], [], f"{len(fuites)} valeur(s) en clair")

    def test_pieges_intacts(self):
        abimes = [p for _, texte, sortie, _ in self.cas for p in PIEGES if p in texte and p not in sortie]
        self.assertEqual(abimes[:20], [])

    def test_restauration(self):
        # Même jeton pour les écritures d'une même valeur : casse des noms de machine (WEB04 / web04),
        # séparateurs des adresses MAC (06-6E-30-D6-3A-BE / 066E30D63ABE)
        def forme(x):
            return re.sub(r"\b([0-9a-f]{2})[:-](?=[0-9a-f]{2}\b)", r"\1", x.casefold())
        for _, texte, sortie, a in self.cas:
            self.assertEqual(forme(a.restaurer(sortie).texte), forme(texte))

    def test_rapide(self):
        self.assertLess(self.duree, 30)


if __name__ == "__main__":
    unittest.main()
