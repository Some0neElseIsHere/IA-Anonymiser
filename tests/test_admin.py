"""Détection pour administrateurs : secrets, comptes, DN, SID et motifs personnalisés.

Chaque cas « doit masquer » a un piège « doit laisser » en face.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from moteur import Anonymiseur  # noqa: E402


def anon(texte, termes=(), motifs=(), types=None):
    a = Anonymiseur()
    return a.anonymiser(texte, termes, types, motifs).texte


class Secrets(unittest.TestCase):
    def test_cle_valeur(self):
        cas = {
            "password=Sup3r!Secret": "password=[SECRET_1]",
            "DB_PASSWORD=hunter2": "DB_PASSWORD=[SECRET_1]",
            "MYSQL_ROOT_PASSWORD: 'p@ss w0rd'": "MYSQL_ROOT_PASSWORD: '[SECRET_1]'",
            '"password": "Azerty123"': '"password": "[SECRET_1]"',
            "spring.datasource.password=Xy9#k": "spring.datasource.password=[SECRET_1]",
            "Server=sql01;User Id=sa;Password=Mdp2026!;": "Server=sql01;User Id=sa;Password=[SECRET_1];",
            "pwd: Lili2024": "pwd: [SECRET_1]",
            "mot de passe : Printemps2026": "mot de passe : [SECRET_1]",
            "api_key=ABCD1234efgh": "api_key=[SECRET_1]",
            "client_secret=zz99-yy88": "client_secret=[SECRET_1]",
            "snmp community=public123": "snmp community=[SECRET_1]",
            "https://api/x?token=abcdef123456&page=2": "https://api/x?token=[SECRET_1]&page=2",
            "AccountKey=dGhpcyBpcyBhIGtleQ==;": "AccountKey=[SECRET_1];",
        }
        for texte, attendu in cas.items():
            with self.subTest(texte=texte):
                self.assertEqual(anon(texte), attendu)

    def test_formes_connues(self):
        cas = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_" + "a1B2" * 9,
            "github_pat_" + "x" * 50,
            "glpat-" + "A" * 20,
            "xoxb-123456789012-abcdefABCDEF",
            "sk-ant-" + "k" * 40,
            "AIza" + "S" * 35,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ]
        for secret in cas:
            with self.subTest(secret=secret[:12]):
                self.assertEqual(anon(f"clé {secret} ici"), "clé [SECRET_1] ici")

    def test_bearer_et_url(self):
        self.assertEqual(anon("Authorization: Bearer abc.DEF-123_456xyz"), "Authorization: Bearer [SECRET_1]")
        self.assertEqual(anon("git clone https://deploy:Tok3nValue@git.acme.local/app.git"),
                         "git clone https://deploy:[SECRET_1]@[FQDN_1]/app.git")
        self.assertEqual(anon("<password>Secr3t</password>"), "<password>[SECRET_1]</password>")

    def test_cle_privee(self):
        cle = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
        self.assertEqual(anon(f"avant\n{cle}\naprès"), "avant\n[SECRET_1]\naprès")

    def test_pieges_secrets(self):
        for texte in [
            "Password expired for user",          # pas de valeur
            "Kerberos pre-auth failed",
            "the password policy is strict",
            "reset-password page",
            "token expired, please login",
            "-----BEGIN CERTIFICATE-----",        # certificat public, pas une clé privée
            "sk-12",                              # trop court
            "passwordless login",
        ]:
            with self.subTest(texte=texte):
                self.assertEqual(anon(texte), texte)

    def test_secret_meme_jeton(self):
        a = Anonymiseur()
        r = a.anonymiser("password=Abc123 puis pwd=Abc123 puis pwd=abc123", [])
        self.assertEqual(r.texte, "password=[SECRET_1] puis pwd=[SECRET_1] puis pwd=[SECRET_2]")
        self.assertEqual(a.restaurer(r.texte).texte, "password=Abc123 puis pwd=Abc123 puis pwd=abc123")


class Comptes(unittest.TestCase):
    def test_domaine_utilisateur(self):
        self.assertEqual(anon(r"Logon ACME\mlefevre OK"), "Logon [COMPTE_1] OK")
        self.assertEqual(anon(r"runas /user:ACME-FR\adm.lefevre cmd"), "runas /user:[COMPTE_1] cmd")

    def test_pieges_domaine(self):
        for texte in [
            r"NT AUTHORITY\SYSTEM",
            r"BUILTIN\Administrators",
            r"HKLM\Software\Microsoft",
            r"HKEY_LOCAL_MACHINE\SOFTWARE",
            r"\\fs02\Compta\Paie_2026",
            r"Compta\Paie_2026",
            r"C:\Windows\SYSTEM32\drivers",
        ]:
            with self.subTest(texte=texte):
                self.assertEqual(anon(texte, types={"COMPTE"}), texte)

    def test_chemins_de_profil(self):
        self.assertEqual(anon(r"C:\Users\mlefevre\Desktop\a.txt"), r"C:\Users\[COMPTE_1]\Desktop\a.txt")
        self.assertEqual(anon(r"C:\Users\Marc Lefevre\AppData"), r"C:\Users\[COMPTE_1]\AppData")
        self.assertEqual(anon("/home/mlefevre/.ssh/id_rsa"), "/home/[COMPTE_1]/.ssh/id_rsa")
        self.assertEqual(anon("/Users/marc/Library"), "/Users/[COMPTE_1]/Library")

    def test_pieges_chemins(self):
        for texte in [r"C:\Users\Public\Documents", r"C:\Users\Default\NTUSER.DAT", "/api/users/123",
                      "/var/log/home/x"]:
            with self.subTest(texte=texte):
                self.assertEqual(anon(texte, types={"COMPTE"}), texte)

    def test_dn(self):
        self.assertEqual(anon("Objet CN=Marc Lefevre,OU=Compta,DC=acme,DC=local (verrouillé)"),
                         "Objet [DN_1] (verrouillé)")
        self.assertEqual(anon("ldap: cn=svc-backup, ou=Services, dc=acme, dc=fr"), "ldap: [DN_1]")

    def test_pieges_dn(self):
        for texte in ["CN=", "x=1, y=2", "OU=Compta"]:
            with self.subTest(texte=texte):
                self.assertEqual(anon(texte, types={"DN"}), texte)

    def test_sid(self):
        self.assertEqual(anon("SID S-1-5-21-3623811015-3361044348-30300820-1013 refusé"), "SID [SID_1] refusé")
        self.assertEqual(anon("S-1-5-18 et S-1-5-32-544"), "S-1-5-18 et S-1-5-32-544")  # SID système


class MotifsPersonnalises(unittest.TestCase):
    def test_motifs(self):
        motifs = [r"PC-\d{4}", r"INC-\d{4}-\d+", r"SRV-[A-Z]+\d*"]
        self.assertEqual(anon("INC-2026-4471 : PC-0815 et srv-paie01 et SRV-DC", motifs=motifs),
                         "[REF_1] : [REF_2] et [REF_3] et [REF_4]")

    def test_motif_invalide_ignore(self):
        self.assertEqual(anon("PC-0815", motifs=["PC-(", r"PC-\d+"]), "[REF_1]")

    def test_motif_vide_ignore(self):
        self.assertEqual(anon("abc", motifs=[r"x*"]), "abc")

    def test_anglais(self):
        a = Anonymiseur("en")
        r = a.anonymiser(r"ACME\jsmith PC-0815", [], None, [r"PC-\d{4}"])
        self.assertEqual(r.texte, "[ACCOUNT_1] [REF_1]")


class PiegesDeLogs(unittest.TestCase):
    def test_textes_techniques_laisses_en_clair(self):
        for texte in [
            "java.lang.NullPointerException at com.acme.app.Service.run(Service.java:42)",
            "spring.datasource.url=jdbc:postgresql://db/app",
            "log4j.rootLogger=INFO, stdout",
            r"NT SERVICE\MSSQLSERVER",
            r"IIS APPPOOL\DefaultAppPool",
            "System.Net.Http.HttpRequestException",
            "kubectl get pods -n kube-system",
            "version 10.0.19045.3693",
        ]:
            with self.subTest(texte=texte):
                self.assertEqual(anon(texte), texte)

    def test_fqdn_reels(self):
        self.assertEqual(anon("db.acme.corp, web01.prod.internal, acme.io, www.acme.co.uk"),
                         "[FQDN_1], [FQDN_2], [FQDN_3], [FQDN_4]")

    def test_restauration_garde_les_antislashs(self):
        texte = r"\\fs02.acme.local\Compta et C:\Users\mlefevre\Desktop et ACME\mlefevre"
        a = Anonymiseur()
        r = a.anonymiser(texte, [])
        self.assertEqual(a.restaurer(r.texte).texte, texte)
        self.assertEqual(a.restaurer(r"\[COMPTE_1\]").texte, "mlefevre")  # échappement Markdown


class LogComplet(unittest.TestCase):
    def test_extrait_de_log(self):
        log = (
            "2026-11-10 08:02 vpn01.acme.local user ACME\\mlefevre from 203.0.113.45 token=9f8e7d6c5b4a\n"
            "2026-11-10 08:03 dc01 CN=Marc Lefevre,OU=Compta,DC=acme,DC=local SID S-1-5-21-1-2-3-1013\n"
            "2026-11-10 08:04 profile C:\\Users\\mlefevre\\AppData loaded, see report.pdf v2.4.1\n"
        )
        a = Anonymiseur()
        r = a.anonymiser(log, [], None, [r"PC-\d{4}"])
        for clair in ("mlefevre", "Marc", "203.0.113.45", "9f8e7d6c5b4a", "S-1-5-21-1-2-3-1013"):
            self.assertNotIn(clair, r.texte)
        for garde in ("report.pdf", "v2.4.1", "dc01", "AppData", "token="):
            self.assertIn(garde, r.texte)
        self.assertEqual(a.restaurer(r.texte).texte, log)


if __name__ == "__main__":
    unittest.main()
