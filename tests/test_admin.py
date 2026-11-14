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
            "Server=sql01;User Id=sa;Password=Mdp2026!;": "Server=sql01;User Id=[COMPTE_1];Password=[SECRET_1];",
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
                         "git clone https://[COMPTE_1]:[SECRET_1]@[FQDN_1]/app.git")
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
                         "Objet CN=[COMPTE_1],OU=Compta,[DN_1] (verrouillé)")
        self.assertEqual(anon("ldap: cn=svc-backup, ou=Services, dc=acme, dc=fr"),
                         "ldap: cn=[COMPTE_1], ou=Services, [DN_1]")
        self.assertEqual(anon("O=Acme SAS, C=FR"), "O=[DN_1], C=FR")

    def test_dn_relie_au_terme(self):
        """Le CN reprend le jeton du terme : l'IA sait que c'est la même personne."""
        texte = "CN=Sophie Bernard,OU=Compta,DC=acme,DC=local ajoutée. Sophie Bernard demande pourquoi."
        self.assertEqual(anon(texte, ["Sophie Bernard"]),
                         "CN=[NOM_1],OU=Compta,[DN_1] ajoutée. [NOM_1] demande pourquoi.")
        # Sans terme : le nom du CN est masqué comme compte, puis reconnu ailleurs dans le texte
        self.assertEqual(anon(texte), "CN=[COMPTE_1],OU=Compta,[DN_1] ajoutée. [COMPTE_1] demande pourquoi.")

    def test_meme_domaine_meme_jeton(self):
        self.assertEqual(anon("CN=a1,DC=acme,DC=local et CN=b2,OU=X,DC=acme,DC=local"),
                         "CN=[COMPTE_1],[DN_1] et CN=[COMPTE_2],OU=X,[DN_1]")

    def test_compte_dans_une_url(self):
        self.assertEqual(anon("https://deploy:Pw1x@repo.acme.local/x et ftp://backup@nas.acme.local"),
                         "https://[COMPTE_1]:[SECRET_1]@[FQDN_1]/x et ftp://[COMPTE_2]@[FQDN_2]")

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


class ValeursConnues(unittest.TestCase):
    def test_valeur_reprise_sans_contexte(self):
        self.assertEqual(anon(r"C:\Users\slefevre\Temp puis user slefevre a copié"),
                         r"C:\Users\[COMPTE_1]\Temp puis user [COMPTE_1] a copié")

    def test_secret_recopie_dans_une_phrase(self):
        a = Anonymiseur()
        a.anonymiser("password=Paie#2026!", [])
        a.valider()
        r = a.anonymiser("le mot de passe c'est Paie#2026! je crois, pas paie#2026!", [])
        self.assertEqual(r.texte, "le mot de passe c'est [SECRET_1] je crois, pas paie#2026!")

    def test_compte_sql(self):
        self.assertEqual(anon("User Id=paie_app;Password=X1y2z3; Login succeeded for 'paie_app'"),
                         "User Id=[COMPTE_1];Password=[SECRET_1]; Login succeeded for '[COMPTE_1]'")

    def test_valeurs_courtes_ignorees(self):
        # « sa » (2 lettres) ne doit pas être masqué partout dans le texte
        self.assertEqual(anon("uid=sa; la salle sa"), "uid=[COMPTE_1]; la salle sa")

    def test_type_desactive_non_propage(self):
        a = Anonymiseur()
        a.anonymiser("10.0.0.1", [])
        a.valider()
        self.assertEqual(a.anonymiser("10.0.0.1", [], types={"EMAIL"}).texte, "10.0.0.1")


class DefautsTrouvesParLesTestsDeMasse(unittest.TestCase):
    def test_pwd_de_sudo_n_est_pas_un_mot_de_passe(self):
        self.assertEqual(anon("sudo: jmoreau : TTY=pts/0 ; PWD=/home/jmoreau ; COMMAND=/bin/ls"),
                         "sudo: [COMPTE_1] : TTY=pts/0 ; PWD=/home/[COMPTE_1] ; COMMAND=/bin/ls")

    def test_pas_de_numero_a_cheval_sur_deux_lignes(self):
        self.assertEqual(anon("/api/users/123\n10.69.114.122 GET"), "/api/users/123\n[IP_1] GET")
        self.assertEqual(anon("tel 06 12 34\n56 78 90"), "tel 06 12 34\n56 78 90")


class CasLimites(unittest.TestCase):
    def test_termes_insensibles_aux_accents(self):
        a = Anonymiseur()
        r = a.anonymiser("Marc Lefèvre, MARC LEFEVRE, marc lefevre, Marc Lefévre", ["Marc Lefèvre"])
        self.assertEqual(r.texte, "[NOM_1], [NOM_1], [NOM_1], [NOM_1]")
        self.assertEqual(a.restaurer("[NOM_1]").texte, "Marc Lefèvre")

    def test_jeton_personnalise_terme_accentue(self):
        a = Anonymiseur()
        a.etiquettes = {"société générale": "CLIENT"}
        self.assertEqual(a.anonymiser("Société Générale et SOCIETE GENERALE", ["Société Générale"]).texte,
                         "[CLIENT] et [CLIENT]")

    def test_conversation_enregistree_avant_les_accents(self):
        """Un état enregistré par une version précédente (clé avec accents) garde ses jetons."""
        ancien = {"valide": {"[NOM_1]": ["NOM", "Marc Lefèvre"]}, "exclus": [],
                  "index": [["NOM", "marc lefèvre", "[NOM_1]"]], "a_annoncer": {}}
        a = Anonymiseur()
        a.charger_etat(ancien)
        self.assertEqual(a.anonymiser("Marc Lefèvre puis Marc Lefevre", ["Marc Lefèvre"]).texte,
                         "[NOM_1] puis [NOM_1]")

    def test_jeton_deja_ecrit_dans_le_texte(self):
        a = Anonymiseur()
        texte = "Modèle : remplacer [IP_1] par l'adresse. Vraie adresse : 10.0.0.9"
        r = a.anonymiser(texte, [])
        self.assertEqual(r.texte, "Modèle : remplacer [IP_1] par l'adresse. Vraie adresse : [IP_2]")
        a.valider()
        self.assertEqual(a.restaurer(r.texte).texte, texte)

    def test_emoji_crlf_tabulations(self):
        for texte in ("🔥 jean.dupont@acme.fr 😀 10.0.0.1", "a 10.0.0.1\r\nb jean@acme.fr\r\n",
                      "user\tACME\\jdoe\tfrom\t10.0.0.2"):
            a = Anonymiseur()
            r = a.anonymiser(texte, [])
            a.valider()
            self.assertEqual(a.restaurer(r.texte).texte, texte)
            self.assertNotIn("10.0.0", r.texte)


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


class JournauxV1104(unittest.TestCase):
    """Trous trouvés avec le log d'incident « rançongiciel » (v1.10.4)."""

    def test_ipv6(self):
        self.assertEqual(anon("depuis 2a01:e0a:1f3:9a40::17 port 50122"), "depuis [IP_1] port 50122")
        self.assertEqual(anon("fe80::1c2b:3cff:fe4d:5e6f%eth0"), "[IP_1]")
        self.assertEqual(anon("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "[IP_1]")

    def test_pas_ipv6(self):
        for texte in ("à 08:39:38", "std::vector", "MAC 00:1A:2B:3C:4D:5E", "dead:beef:", "a::b"):
            self.assertNotIn("[IP_", anon(texte), texte)

    def test_bouclage_en_clair(self):
        self.assertEqual(anon("ping 127.0.0.1, ::1 et 0.0.0.0"), "ping 127.0.0.1, ::1 et 0.0.0.0")

    def test_net_use(self):
        self.assertEqual(anon('net use \\\\fs01\\C$ /user:ACME\\svc Wint3r!Maint2026"'),
                         'net use \\\\[FQDN_1]\\C$ /user:[COMPTE_1] [SECRET_1]"')
        self.assertEqual(anon("net use Z: \\\\nas\\data S3cret! /user:backup"),
                         "net use Z: \\\\[FQDN_1]\\data [SECRET_1] /user:[COMPTE_1]")
        self.assertEqual(anon("net use \\\\nas\\data * /user:jdoe"), "net use \\\\[FQDN_1]\\data * /user:[COMPTE_1]")

    def test_comptes_des_journaux(self):
        self.assertEqual(anon("Login failed for user 'app_paie'."), "Login failed for user '[COMPTE_1]'.")
        self.assertEqual(anon("Login failed for user 'NT AUTHORITY\\ANONYMOUS LOGON'"),
                         "Login failed for user 'NT AUTHORITY\\ANONYMOUS LOGON'")
        self.assertEqual(anon("Accepted publickey for jdupont from"), "Accepted publickey for [COMPTE_1] from")
        self.assertEqual(anon("Failed password for invalid user oracle from"),
                         "Failed password for invalid user [COMPTE_1] from")
        self.assertEqual(anon("session opened for user mdurand by"), "session opened for user [COMPTE_1] by")
        self.assertEqual(anon("sudo:   pmartin : TTY=pts/0"), "sudo:   [COMPTE_1] : TTY=pts/0")
        self.assertEqual(anon("a ticket for user experience"), "a ticket for user experience")


class JournauxReels(unittest.TestCase):
    """Défauts trouvés sur de vrais journaux (loghub, OTRF Security-Datasets), v1.11.0."""

    def test_empreintes_et_guid_ne_sont_pas_des_numeros(self):
        for texte in ("MD5=BE57D3232C688595C3276DB79B66BD35", "{39e4a257-f132-5f8b-1000-000000000700}",
                      "{00000000-0000-0000-0000-000000000000}", "BIOS-e820: 0000000000100000",
                      "value=\"140705280950272\"", "ntpd: time reset +0.182379 s"):
            self.assertEqual(anon(texte), texte, texte)

    def test_numeros_valides_toujours_masques(self):
        self.assertEqual(anon("carte 4111111111111111"), "carte [CARTE_1]")
        self.assertEqual(anon("FR7630006000011234567890189"), "[IBAN_1]")

    def test_versions_ne_sont_pas_des_ip(self):
        for texte in ("wcp.dll version 0.0.0.6", "Version=4.0.0.0", "amd64~~6.1.1.0", "0:0:0:0:0:0:0:1"):
            self.assertEqual(anon(texte), texte, texte)

    def test_mots_courants_pas_comptes(self):
        for texte in ("Virtual Account:\t\tNo", "User: NT AUTHORITY\\SYSTEM", "(uid=0)", "Elevated Token:\t\tNo",
                      "Target Account:\n\tSecurity ID:\tS-1-0-0", "pam_unix(passwd:chauthtok): ok",
                      "Service Account:   LocalSystem"):
            self.assertEqual(anon(texte), texte, texte)

    def test_compte_propage_a_l_identique(self):
        self.assertEqual(anon("session closed for user root\nROOT LOGIN ON tty2, PCI Root Bridge"),
                         "session closed for user [COMPTE_1]\nROOT LOGIN ON tty2, PCI Root Bridge")

    def test_espaces_de_noms_et_fichiers(self):
        for texte in ("System.Security", "Microsoft.PowerShell.Security", "com.apple.xpc.activity",
                      "REG.EXE-E7E8BD26.pf", "Weather.app", "subject.OU"):
            self.assertEqual(anon(texte), texte, texte)

    def test_evenement_windows(self):
        texte = ("New Logon:\n\tAccount Name:\t\tpgustavo\n\tAccount Domain:\t\tTHESHIRE\n"
                 "\tWorkstation Name:\tWORKSTATION6\n\tAccount Name:\t\tMORDORDC$\n\tAccount Name:\t\t-")
        self.assertEqual(anon(texte), "New Logon:\n\tAccount Name:\t\t[COMPTE_1]\n\tAccount Domain:\t\t[FQDN_1]\n"
                                      "\tWorkstation Name:\t[FQDN_2]\n\tAccount Name:\t\t[FQDN_3]$\n\tAccount Name:\t\t-")

    def test_noms_de_machine(self):
        self.assertEqual(anon("Nov 12 08:01:02 srv-web01 sshd[123]: ok"), "Nov 12 08:01:02 [FQDN_1] sshd[123]: ok")
        self.assertEqual(anon("   Host Name . . . . . . . . . . . . : PC-0815"),
                         "   Host Name . . . . . . . . . . . . : [FQDN_1]")
        self.assertEqual(anon("copie vers \\\\fs01\\Direction"), "copie vers \\\\[FQDN_1]\\Direction")
        self.assertEqual(anon("Nov 12 08:01:02 localhost kernel: x"), "Nov 12 08:01:02 localhost kernel: x")

    def test_domaine_en_minuscules(self):
        self.assertEqual(anon("User: ACME\\jdoe\nacme\\jdoe\nAcme SAS, com.acme.payroll"),
                         "User: [COMPTE_1]\n[FQDN_1]\\[COMPTE_2]\nAcme SAS, com.acme.payroll")

    def test_comptes_linux_et_web(self):
        self.assertEqual(anon("New session 4 of user jdupont."), "New session 4 of user [COMPTE_1].")
        self.assertEqual(anon("password changed for jdupont"), "password changed for [COMPTE_1]")
        self.assertEqual(anon('10.1.2.3 - jdupont [12/Nov/2026:08:00:00 +0100] "GET / HTTP/1.1" 200'),
                         '[IP_1] - [COMPTE_1] [12/Nov/2026:08:00:00 +0100] "GET / HTTP/1.1" 200')
        self.assertEqual(anon("User name                    jdupont"), "User name                    [COMPTE_1]")


if __name__ == "__main__":
    unittest.main()
