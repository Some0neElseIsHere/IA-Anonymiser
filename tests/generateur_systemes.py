"""Générateur de journaux Windows et Linux réalistes, avec la liste exacte de ce qui doit être masqué.

document(u, n) renvoie (texte, sensibles, pieges) : les valeurs sensibles ne doivent plus apparaître dans le texte
anonymisé, les pièges doivent y rester intacts. Les noms complets des personnes sont donnés comme termes,
comme le ferait un utilisateur ; tout le reste doit être trouvé automatiquement.
"""
import datetime as dt
import hashlib
import random
import uuid

PRENOMS = ["Camille", "Thomas", "Ines", "Julien", "Sophie", "Karim", "Elodie", "Nicolas", "Laura", "Hugo", "Manon",
           "Lucas", "Chloe", "Yanis", "Sarah", "Mathis", "Lea", "Adam", "Emma", "Noah"]
NOMS = ["Rousseau", "Girard", "Benali", "Moreau", "Lemaitre", "Haddad", "Faure", "Perrin", "Chevalier", "Marchand",
        "Garnier", "Fabre", "Mercier", "Dupuis", "Lambert", "Bonnet", "Francois", "Martinez", "Legrand", "Gauthier"]
SOCIETES = [("Vallorie", "vallorie"), ("Kestrel Medical", "kestrel"), ("Brenneville", "brenneville"),
            ("Ostral Energie", "ostral"), ("Mirabeau Assurances", "mirabeau")]
PIEGES = ["NT AUTHORITY\\SYSTEM", "S-1-5-18", "BUILTIN\\Administrators", "0xC000006A", "%%2313", "KB5044284",
          "C:\\Windows\\System32\\svchost.exe", "10.0.19045.4651", "Microsoft-Windows-Security-Auditing",
          "{00000000-0000-0000-0000-000000000000}", "0x0000000000100000", "127.0.0.1", "::1",
          "/usr/sbin/sshd", "pam_unix(sshd:session)", "systemd-logind", "Linux version 6.8.0-45-generic",
          "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "java.lang.NullPointerException",
          "WinRM", "Kerberos", "NTLM V2", "SHA256=", "LogonType 3", "System.Management.Automation"]


class Univers:
    def __init__(self, graine):
        r = self.r = random.Random(graine)
        self.societe, base = r.choice(SOCIETES)
        self.netbios = base.upper()[:12]
        self.domaine = f"{base}.local"
        self.externe = f"{base}-{r.choice(['groupe', 'sa', 'france', 'corp'])}.fr"
        self.personnes = []
        for p, n in r.sample(list(zip(PRENOMS, NOMS)), 8):
            login = (p[0] + n).lower()
            self.personnes.append({"prenom": p, "nom": n, "login": login,
                                   "email": f"{p.lower()}.{n.lower()}@{self.externe}",
                                   "rid": r.randint(1100, 9999)})
        self.sid = f"S-1-5-21-{r.randint(10**9, 4 * 10**9)}-{r.randint(10**9, 4 * 10**9)}-{r.randint(10**8, 10**9)}"
        self.postes = [f"{r.choice(['PC', 'WS', 'LT'])}-{r.randint(1000, 9999)}" for _ in range(6)]
        self.serveurs = [f"{x}{r.randint(1, 9):02d}" for x in r.sample(["dc", "fs", "sql", "web", "app", "exch",
                                                                         "backup", "rds", "ca", "wsus"], 6)]
        self.ip = {h: f"10.{r.randint(1, 250)}.{r.randint(1, 250)}.{r.randint(2, 250)}"
                   for h in self.postes + self.serveurs}
        self.attaquant = f"{r.choice([45, 91, 185, 193])}.{r.randint(1, 250)}.{r.randint(1, 250)}.{r.randint(2, 250)}"
        self.mac = {h: ":".join(f"{r.randint(0, 255):02X}" for _ in range(6)) for h in self.postes}
        self.mots_de_passe = [f"{r.choice(['Hiver', 'Soleil', 'Azerty', 'Paris'])}{r.randint(10, 99)}!"
                              f"{r.choice('#$%&')}{r.randint(100, 999)}" for _ in range(3)]
        self.sensibles, self.termes = set(), []
        for x in self.personnes:
            self.termes.append(f"{x['prenom']} {x['nom']}")

    def note(self, *valeurs):
        self.sensibles.update(valeurs)
        return valeurs[0] if len(valeurs) == 1 else valeurs


def _temps(u):
    debut = dt.datetime(2026, 11, u.r.randint(1, 12), u.r.randint(0, 23), u.r.randint(0, 59))
    while True:
        debut += dt.timedelta(seconds=u.r.randint(1, 300))
        yield debut


def security(u, t, n=6):
    """Événements Security rendus comme dans l'Observateur d'événements."""
    r, blocs = u.r, []
    for _ in range(n):
        x, poste = r.choice(u.personnes), r.choice(u.postes)
        srv = r.choice(u.serveurs)
        u.note(x["login"], u.netbios, poste, srv.upper(), u.ip[poste], f"{srv}.{u.domaine}")
        eid = r.choice([4624, 4625, 4688, 4720, 4728, 4740, 4776])
        tete = f"{next(t):%d/%m/%Y %H:%M:%S}  {srv}.{u.domaine}  Microsoft-Windows-Security-Auditing  {eid}"
        sujet = (f"Subject:\n\tSecurity ID:\t\t{u.sid}-{x['rid']}\n\tAccount Name:\t\t{x['login']}\n"
                 f"\tAccount Domain:\t\t{u.netbios}\n\tLogon ID:\t\t0x{r.randint(0x10000, 0xFFFFFF):X}")
        u.note(f"{u.sid}-{x['rid']}")
        if eid == 4624:
            corps = (f"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n"
                     f"\tAccount Name:\t\t{srv.upper()}$\n\tAccount Domain:\t\t{u.netbios}\n\nLogon Information:\n"
                     f"\tLogon Type:\t\t3\n\nNew Logon:\n\tSecurity ID:\t\t{u.sid}-{x['rid']}\n"
                     f"\tAccount Name:\t\t{x['login']}\n\tAccount Domain:\t\t{u.netbios}\n"
                     f"\tLogon GUID:\t\t{{{uuid.UUID(int=r.getrandbits(128))}}}\n\nNetwork Information:\n"
                     f"\tWorkstation Name:\t{poste}\n\tSource Network Address:\t{u.ip[poste]}\n\tSource Port:\t\t"
                     f"{r.randint(49152, 65535)}\n\nDetailed Authentication Information:\n\tLogon Process:\t\tKerberos\n"
                     f"\tAuthentication Package:\tKerberos")
        elif eid == 4625:
            corps = (f"An account failed to log on.\n\n{sujet}\n\nAccount For Which Logon Failed:\n"
                     f"\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t{x['login']}\n\tAccount Domain:\t\t{u.netbios}\n\n"
                     f"Failure Information:\n\tFailure Reason:\t\t%%2313\n\tStatus:\t\t\t0xC000006D\n"
                     f"\tSub Status:\t\t0xC000006A\n\nNetwork Information:\n\tWorkstation Name:\t{poste}\n"
                     f"\tSource Network Address:\t{u.attaquant}\n\tSource Port:\t\t0")
            u.note(u.attaquant)
        elif eid == 4688:
            mdp = r.choice(u.mots_de_passe)
            u.note(mdp)
            corps = (f"A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\t{u.sid}-{x['rid']}\n"
                     f"\tAccount Name:\t\t{x['login']}\n\tAccount Domain:\t\t{u.netbios}\n\nProcess Information:\n"
                     f"\tNew Process Name:\tC:\\Windows\\System32\\net.exe\n\tProcess Command Line:\t"
                     f"net use \\\\{srv}\\C$ /user:{u.netbios}\\{x['login']} {mdp}")
        elif eid in (4720, 4728):
            cible = r.choice(u.personnes)
            u.note(cible["login"])
            corps = (f"A user account was {'created' if eid == 4720 else 'added to a security-enabled global group'}."
                     f"\n\n{sujet}\n\nNew Account:\n\tSecurity ID:\t\t{u.sid}-{cible['rid']}\n"
                     f"\tAccount Name:\t\t{cible['login']}\n\tAccount Domain:\t\t{u.netbios}\n\nAttributes:\n"
                     f"\tSAM Account Name:\t{cible['login']}\n\tDisplay Name:\t\t{cible['prenom']} {cible['nom']}\n"
                     f"\tUser Principal Name:\t{cible['login']}@{u.domaine}")
            u.note(f"{cible['login']}@{u.domaine}", f"{u.sid}-{cible['rid']}")
        elif eid == 4740:
            corps = (f"A user account was locked out.\n\n{sujet}\n\nAccount That Was Locked Out:\n"
                     f"\tSecurity ID:\t\t{u.sid}-{x['rid']}\n\tAccount Name:\t\t{x['login']}\n\n"
                     f"Additional Information:\n\tCaller Computer Name:\t{poste}")
        else:
            corps = (f"The computer attempted to validate the credentials for an account.\n\n"
                     f"Authentication Package:\tMICROSOFT_AUTHENTICATION_PACKAGE_V1_0\nLogon Account:\t{x['login']}\n"
                     f"Source Workstation:\t{poste}\nError Code:\t0xC000006A")
        blocs.append(f"{tete}\n{corps}\n")
    return "\n".join(blocs)


def sysmon(u, t, n=5):
    r, blocs = u.r, []
    for _ in range(n):
        x, poste = r.choice(u.personnes), r.choice(u.postes)
        u.note(x["login"], u.netbios, poste, u.ip[poste])
        h = hashlib.md5(str(r.random()).encode()).hexdigest().upper()
        if r.random() < 0.5:
            corps = (f"Process Create:\nRuleName: -\nUtcTime: {next(t):%Y-%m-%d %H:%M:%S.%f}\n"
                     f"ProcessGuid: {{{uuid.UUID(int=r.getrandbits(128))}}}\nProcessId: {r.randint(100, 9999)}\n"
                     f"Image: C:\\Users\\{x['login']}\\AppData\\Local\\Temp\\upd.exe\nFileVersion: 10.0.19041.1\n"
                     f"CommandLine: powershell -nop -w hidden -enc "
                     f"{''.join(r.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/') for _ in range(400))}\n"
                     f"CurrentDirectory: C:\\Users\\{x['login']}\\\nUser: {u.netbios}\\{x['login']}\n"
                     f"LogonGuid: {{{uuid.UUID(int=r.getrandbits(128))}}}\nIntegrityLevel: Medium\n"
                     f"Hashes: MD5={h},SHA256={hashlib.sha256(h.encode()).hexdigest().upper()},IMPHASH={h[::-1]}")
        else:
            corps = (f"Network connection detected:\nRuleName: -\nUtcTime: {next(t):%Y-%m-%d %H:%M:%S.%f}\n"
                     f"Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
                     f"User: {u.netbios}\\{x['login']}\nProtocol: tcp\nInitiated: true\nSourceIsIpv6: false\n"
                     f"SourceIp: {u.ip[poste]}\nSourceHostname: {poste}.{u.domaine}\nSourcePort: {r.randint(49152, 65535)}\n"
                     f"DestinationIp: {u.attaquant}\nDestinationPort: 443")
            u.note(u.attaquant, f"{poste}.{u.domaine}")
        blocs.append(f"{next(t):%Y-%m-%d %H:%M:%S} {poste}.{u.domaine} Microsoft-Windows-Sysmon/Operational\n{corps}\n")
    return "\n".join(blocs)


def ipconfig(u, t):
    poste = u.r.choice(u.postes)
    u.note(poste, u.domaine, u.ip[poste], u.mac[poste].replace(":", "-"))
    return (f"Windows IP Configuration\n\n   Host Name . . . . . . . . . . . . : {poste}\n"
            f"   Primary Dns Suffix  . . . . . . . : {u.domaine}\n   Node Type . . . . . . . . . . . . : Hybrid\n"
            f"   IP Routing Enabled. . . . . . . . : No\n\nEthernet adapter Ethernet:\n\n"
            f"   Physical Address. . . . . . . . . : {u.mac[poste].replace(':', '-')}\n"
            f"   IPv4 Address. . . . . . . . . . . : {u.ip[poste]}(Preferred)\n"
            f"   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n")


def get_aduser(u, t):
    x = u.r.choice(u.personnes)
    u.note(x["login"], f"{x['login']}@{u.domaine}", f"{u.sid}-{x['rid']}", "DC=" + u.domaine.split(".")[0])
    return (f"PS C:\\> Get-ADUser {x['login']} -Properties *\n\nDistinguishedName : CN={x['prenom']} {x['nom']},"
            f"OU=Utilisateurs,DC={u.domaine.split('.')[0]},DC=local\nEnabled           : True\n"
            f"GivenName         : {x['prenom']}\nName              : {x['prenom']} {x['nom']}\n"
            f"ObjectClass       : user\nSamAccountName    : {x['login']}\nSID               : {u.sid}-{x['rid']}\n"
            f"Surname           : {x['nom']}\nUserPrincipalName : {x['login']}@{u.domaine}\n")


def net_user(u, t):
    x = u.r.choice(u.personnes)
    u.note(x["login"])
    return (f"C:\\> net user {x['login']} /domain\nUser name                    {x['login']}\n"
            f"Full Name                    {x['prenom']} {x['nom']}\nAccount active               Yes\n"
            f"Last logon                   {next(t):%d/%m/%Y %H:%M:%S}\nThe command completed successfully.\n")


def transcript(u, t):
    x, poste = u.r.choice(u.personnes), u.r.choice(u.postes)
    u.note(x["login"], u.netbios, poste)
    return (f"**********************\nWindows PowerShell transcript start\nStart time: {next(t):%Y%m%d%H%M%S}\n"
            f"Username: {u.netbios}\\{x['login']}\nRunAs User: {u.netbios}\\{x['login']}\n"
            f"Machine: {poste} (Microsoft Windows NT 10.0.19045.0)\nHost Application: powershell.exe\n"
            f"**********************\nPS C:\\Users\\{x['login']}> whoami\n{u.netbios.lower()}\\{x['login']}\n")


def auth_log(u, t, n=14):
    r, lignes = u.r, []
    for _ in range(n):
        x, srv = r.choice(u.personnes), r.choice(u.serveurs)
        u.note(x["login"], srv)
        d = next(t)
        tete = f"{d:%b} {d.day:>2} {d:%H:%M:%S} {srv}"
        pid = r.randint(1000, 60000)
        k = r.randrange(9)
        if k == 0:
            ip = r.choice(list(u.ip.values()))
            u.note(ip)
            lignes.append(f"{tete} sshd[{pid}]: Accepted publickey for {x['login']} from {ip} port {r.randint(40000, 65000)} ssh2: RSA SHA256:{hashlib.sha256(str(pid).encode()).hexdigest()[:43]}")
        elif k == 1:
            u.note(u.attaquant)
            lignes.append(f"{tete} sshd[{pid}]: Failed password for invalid user {x['login']} from {u.attaquant} port {r.randint(40000, 65000)} ssh2")
        elif k == 2:
            lignes.append(f"{tete} sudo[{pid}]:   {x['login']} : TTY=pts/0 ; PWD=/home/{x['login']} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
        elif k == 3:
            lignes.append(f"{tete} sshd[{pid}]: pam_unix(sshd:session): session opened for user {x['login']}(uid={r.randint(1000, 2000)}) by (uid=0)")
        elif k == 4:
            lignes.append(f"{tete} systemd-logind[{pid}]: New session {r.randint(1, 900)} of user {x['login']}.")
        elif k == 5:
            lignes.append(f"{tete} useradd[{pid}]: new user: name={x['login']}, UID={r.randint(1000, 2000)}, GID=100, home=/home/{x['login']}, shell=/bin/bash, from=/dev/pts/0")
        elif k == 6:
            lignes.append(f"{tete} passwd[{pid}]: pam_unix(passwd:chauthtok): password changed for {x['login']}")
        elif k == 7:
            lignes.append(f"{tete} su[{pid}]: pam_unix(su-l:session): session opened for user root(uid=0) by {x['login']}(uid={r.randint(1000, 2000)})")
        else:
            lignes.append(f"{tete} CRON[{pid}]: pam_unix(cron:session): session closed for user {x['login']}")
    return "\n".join(lignes) + "\n"


def journal(u, t, n=8):
    r, lignes = u.r, []
    for _ in range(n):
        x, srv = r.choice(u.personnes), r.choice(u.serveurs)
        u.note(srv, f"{srv}.{u.domaine}")
        d = next(t)
        k = r.randrange(3)
        if k == 0:
            u.note(x["login"])
            lignes.append(f"{d:%Y-%m-%dT%H:%M:%S}+0100 {srv} systemd[1]: Started Session {r.randint(1, 99)} of user {x['login']}.")
        elif k == 1:
            lignes.append(f"{d:%Y-%m-%dT%H:%M:%S}+0100 {srv} kernel: [ {r.random() * 1000:.6f}] Linux version 6.8.0-45-generic (buildd@lcy02-amd64) BIOS-e820: 0x0000000000100000")
        else:
            lignes.append(f"{d:%Y-%m-%dT%H:%M:%S}+0100 {srv} nginx[{r.randint(100, 999)}]: upstream timed out while connecting to upstream, client: {u.attaquant}, server: {srv}.{u.domaine}")
            u.note(u.attaquant)
    return "\n".join(lignes) + "\n"


def auditd(u, t, n=5):
    r, lignes = u.r, []
    for _ in range(n):
        x, poste = r.choice(u.personnes), r.choice(u.postes)
        u.note(x["login"], f"{poste.lower()}.{u.domaine}", u.ip[poste])
        lignes.append(f"type=USER_LOGIN msg=audit({r.randint(1_700_000_000, 1_800_000_000)}.{r.randint(100, 999)}:{r.randint(100, 9999)}): "
                      f"pid={r.randint(1000, 9999)} uid=0 auid={r.randint(1000, 2000)} ses={r.randint(1, 99)} "
                      f"msg='op=login acct=\"{x['login']}\" exe=\"/usr/sbin/sshd\" hostname={poste.lower()}.{u.domaine} "
                      f"addr={u.ip[poste]} terminal=ssh res={r.choice(['success', 'failed'])}'")
    return "\n".join(lignes) + "\n"


def acces_web(u, t, n=6):
    r, lignes = u.r, []
    for _ in range(n):
        x, poste = r.choice(u.personnes), r.choice(u.postes)
        u.note(x["login"], u.ip[poste], x["email"])
        d = next(t)
        lignes.append(f'{u.ip[poste]} - {x["login"]} [{d:%d/%b/%Y:%H:%M:%S} +0100] "GET /intranet/rh/fiche.php?mail='
                      f'{x["email"]} HTTP/1.1" 200 {r.randint(500, 9000)} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')
    return "\n".join(lignes) + "\n"


def passwd(u, t):
    lignes = ["root:x:0:0:root:/root:/bin/bash", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"]
    for x in u.r.sample(u.personnes, 3):
        u.note(x["login"])
        lignes.append(f"{x['login']}:x:{u.r.randint(1000, 2000)}:100:{x['prenom']} {x['nom']},,,:/home/{x['login']}:/bin/bash")
    return "\n".join(lignes) + "\n"


FORMATS = [security, security, sysmon, ipconfig, get_aduser, net_user, transcript, auth_log, auth_log, journal,
           auditd, acces_web, passwd]


def document(u, n_blocs=4):
    t = _temps(u)
    blocs = [f(u, t) for f in u.r.sample(FORMATS, n_blocs)]
    blocs.append("Pièges : " + ", ".join(u.r.sample(PIEGES, 6)))
    return "\n".join(blocs)
