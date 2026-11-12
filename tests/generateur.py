"""Générateur de logs fictifs pour les tests de masse.

Chaque document est produit avec la liste exacte des valeurs sensibles qu'il contient (qui ne doivent
jamais apparaître dans le texte anonymisé) et des pièges (qui doivent rester intacts).
Tout est déterministe : une graine donne toujours les mêmes documents.
"""
import random

PRENOMS = ["Jean", "Sophie", "Marc", "Claire", "Luc", "Emma", "Hugo", "Léa", "Nicolas", "Inès", "Éric", "Zoé"]
NOMS = ["Dupont", "Bernard", "Lefèvre", "Martin", "Moreau", "Girard", "Rousseau", "Fontaine", "Chevalier", "Roux"]
ENTREPRISES = ["Acme Industries", "Durand Logistique", "Polaris Conseil", "Nordis SA", "Vertigo Systems"]
DOMAINE = "acme-industries"
SUFFIXES = ["local", "fr", "corp", "lan", "internal", "com"]
SERVICES = ["dc", "srv-paie", "sql", "web", "nas", "vpn-gw", "proxy", "erp", "backup", "mail"]

PIEGES = [
    "java.lang.NullPointerException at com.acme.payroll.Export.run(Export.java:42)",
    "spring.datasource.url=jdbc:sqlserver://db:1433",
    "NT AUTHORITY\\SYSTEM",
    "BUILTIN\\Administrators",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SyncSvc",
    "S-1-5-18",
    "-----BEGIN CERTIFICATE-----",
    "report.pdf",
    "nightly_full.tar.gz",
    "version 4.2.7",
    "C:\\Users\\Public\\Documents",
    "/api/users/123",
    "Password expired for user",
    "token expired, please login",
    "Kerberos pre-auth failed",
    "System.Net.Http.HttpRequestException",
    "kubectl get pods -n kube-system",
    "HTTP/1.1\" 200 512",
    "2026-11-12T08:15:00Z",
    "PID 4242",
]


def luhn(prefixe, longueur=16):
    chiffres = [int(c) for c in prefixe]
    while len(chiffres) < longueur - 1:
        chiffres.append(random.randint(0, 9))
    somme = 0
    for i, c in enumerate(reversed(chiffres)):
        somme += (c * 2 - 9 if c * 2 > 9 else c * 2) if i % 2 == 0 else c
    return "".join(map(str, chiffres)) + str((10 - somme % 10) % 10)


class Univers:
    """Un parc fictif : personnes, machines, comptes, secrets… réutilisés d'un document à l'autre."""

    def __init__(self, graine):
        random.seed(graine)
        self.personnes = [(p, n) for p in PRENOMS for n in NOMS]
        random.shuffle(self.personnes)
        self.personnes = self.personnes[:12]
        self.entreprises = random.sample(ENTREPRISES, 3)
        self.machines = [f"{s}{random.randint(1, 9):02d}.{DOMAINE}.{random.choice(SUFFIXES)}" for s in SERVICES]
        self.postes = [f"PC-{random.randint(1000, 9999)}" for _ in range(5)]
        self.tickets = [f"INC-2026-{random.randint(1000, 9999)}" for _ in range(3)]
        self.ips = [f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(8)]
        self.ips += [f"203.0.113.{random.randint(1, 254)}", f"198.51.100.{random.randint(1, 254)}"]
        self.macs = [":".join(f"{random.randint(0, 255):02X}" for _ in range(6)) for _ in range(4)]
        self.comptes = [self.identifiant(p) for p in self.personnes]
        self.mots_de_passe = [f"{random.choice(['Paie', 'Hiver', 'Acme', 'Zz'])}{random.randint(10, 99)}#{random.choice('!$%&')}{random.randint(100, 999)}"
                              for _ in range(5)]
        self.sid = f"S-1-5-21-{random.randint(10**9, 4 * 10**9)}-{random.randint(10**9, 4 * 10**9)}-{random.randint(10**7, 10**9)}"
        self.cartes = [luhn("4"), luhn("5" + str(random.randint(1, 5)))]
        self.iban = "FR76 3000 6000 0112 3456 7890 189"
        self.telephones = [f"06 {random.randint(10, 99)} {random.randint(10, 99)} {random.randint(10, 99)} {random.randint(10, 99)}"
                           for _ in range(4)]

    @staticmethod
    def identifiant(personne):
        prenom, nom = personne
        sans_accent = str.maketrans("éèêëàâîïôûùçÉÈ", "eeeeaaiiouucEE")
        return (prenom[0] + nom).lower().translate(sans_accent)

    def email(self, i):
        prenom, nom = self.personnes[i]
        sans_accent = str.maketrans("éèêëàâîïôûùçÉÈ", "eeeeaaiiouucEE")
        return f"{prenom.lower()}.{nom.lower()}@{DOMAINE}.fr".translate(sans_accent)

    def termes(self):
        """Ce qu'un utilisateur déclarerait : noms complets, entreprises."""
        return [f"{p} {n}" for p, n in self.personnes] + self.entreprises

    def motifs(self):
        return [r"PC-\d{4}", r"INC-\d{4}-\d+"]


def document(u, numero):
    """Un document (texte, valeurs sensibles, pièges) d'un format choisi selon le numéro."""
    random.seed(numero * 7919)
    sensibles, pieges, lignes = set(), set(), []

    def s(valeur):
        sensibles.add(valeur)
        return valeur

    def piege():
        valeur = random.choice(PIEGES)
        pieges.add(valeur)
        return valeur

    i, j = random.randrange(len(u.personnes)), random.randrange(len(u.personnes))
    nom_i = f"{u.personnes[i][0]} {u.personnes[i][1]}"
    nom_j = f"{u.personnes[j][0]} {u.personnes[j][1]}"
    machine, machine2 = random.sample(u.machines, 2)
    ip, ip2 = random.sample(u.ips, 2)
    poste = random.choice(u.postes)
    compte = u.comptes[i]
    mdp = random.choice(u.mots_de_passe)
    format_ = numero % 8

    if format_ == 0:  # journal de sécurité Windows
        for _ in range(random.randint(4, 10)):
            evt = random.choice([4624, 4625, 4672, 4740, 4768])
            lignes.append(f"2026-11-12 08:{random.randint(0, 59):02d}:{random.randint(0, 59):02d} {s(machine)} Security {evt} "
                          f"Account: ACME\\{s(compte)} Source: {s(ip)} Workstation: {s(poste)} | {piege()}")
        lignes.append(f"SID {s(u.sid)} — objet CN={s(nom_i)},OU=Comptabilite,DC={DOMAINE},DC=local modifié")
        sensibles.add(DOMAINE)
    elif format_ == 1:  # syslog Linux
        for _ in range(random.randint(4, 10)):
            lignes.append(f"Nov 12 08:{random.randint(0, 59):02d}:01 {s(machine.split('.')[0])}.{DOMAINE}.local sshd[{random.randint(100, 9999)}]: "
                          f"Accepted publickey for {compte} from {s(ip)} port {random.randint(1024, 65535)} | {piege()}")
            sensibles.add(f"{machine.split('.')[0]}.{DOMAINE}.local")
        lignes.append(f"sudo: {compte} : TTY=pts/0 ; PWD=/home/{s(compte)} ; COMMAND=/bin/cat /etc/shadow")
    elif format_ == 2:  # nginx / accès web avec jetons
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI" + "".join(random.choices("abcdefghijkl", k=12)) + "In0." + "".join(random.choices("ABCDEFabcdef0123456789", k=30))
        for _ in range(random.randint(3, 8)):
            lignes.append(f'{s(ip2)} - - [12/Nov/2026:08:{random.randint(10, 59)}:00 +0100] "GET /api/v1/salaires?token={s("tk" + str(random.randint(10**8, 10**9)))} '
                          f'HTTP/1.1" 200 512 "Authorization: Bearer {s(jwt)}" | {piege()}')
    elif format_ == 3:  # lignes JSON
        for _ in range(random.randint(3, 8)):
            lignes.append('{"ts":"2026-11-12T08:15:00Z","host":"' + s(machine) + '","user":"' + s(u.email(i)) +
                          '","src":"' + s(ip) + '","password":"' + s(mdp) + '","note":"' + piege() + '"}')
    elif format_ == 4:  # CSV d'export RH
        lignes.append("nom;email;telephone;iban;carte;poste")
        for k in random.sample(range(len(u.personnes)), 4):
            n = f"{u.personnes[k][0]} {u.personnes[k][1]}"
            lignes.append(f"{s(n)};{s(u.email(k))};{s(random.choice(u.telephones))};{s(u.iban)};{s(random.choice(u.cartes))};{s(random.choice(u.postes))}")
        lignes.append(piege())
    elif format_ == 5:  # transcription PowerShell
        aws = "AKIA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=16))
        gh = "ghp_" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=36))
        lignes += [
            f"PS C:\\Users\\{s(compte)}> Invoke-WebRequest -Uri https://deploy:{s(mdp)}@{s(machine2)}/sync.ps1",
            f"PS C:\\Users\\{s(compte)}> $env:GH = \"{s(gh)}\"",
            f"PS C:\\Users\\{s(compte)}> Set-Content .aws\\credentials \"aws_access_key_id = {s(aws)}\"",
            f"PS C:\\Users\\{s(compte)}> Get-ADUser -Identity {compte} | {piege()}",
            f"Server=sql01;Database=Paie;User Id=paie_app;Password={s(mdp)};",
        ]
        sensibles.update(["deploy", "paie_app"])
    elif format_ == 6:  # ticket en français, texte libre
        lignes += [
            f"Ticket {s(random.choice(u.tickets))} ouvert par {s(nom_i)} ({s(random.choice(u.telephones))}).",
            f"{s(nom_j)}, de chez {s(random.choice(u.entreprises))}, signale que le poste {s(poste)} ne démarre plus.",
            f"Adresse MAC {s(random.choice(u.macs))}, IP {s(ip)}, serveur {s(machine)}.",
            f"Remboursement sur l'IBAN {s(u.iban)}, carte {s(random.choice(u.cartes))}. {piege()}",
            f"Pour info : {piege()}.",
        ]
    else:  # pare-feu + clé privée collée par erreur
        for _ in range(random.randint(3, 8)):
            lignes.append(f"FW DROP src={s(ip)} dst={s(ip2)} mac={s(random.choice(u.macs))} proto=TCP dport=445 | {piege()}")
        lignes += ["-----BEGIN OPENSSH PRIVATE KEY-----", s("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU" + str(numero)),
                   "-----END OPENSSH PRIVATE KEY-----"]
    return "\n".join(lignes), sensibles, pieges
