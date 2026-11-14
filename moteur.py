"""Moteur d'IA-Anonymiser : détection des données personnelles, jetons et restauration.

Les correspondances jeton -> valeur restent en mémoire uniquement.
"""
import bisect
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field

# Préfixe des jetons selon la langue de l'interface : [NOM_1] en français, [NAME_1] en anglais.
PREFIXES = {
    "fr": {"EMAIL": "EMAIL", "TEL": "TEL", "IBAN": "IBAN", "CARTE": "CARTE", "SECU": "SECU",
           "IP": "IP_privée", "IPPUB": "IP_PUB", "MAC": "MAC", "FQDN": "FQDN", "SECRET": "SECRET", "COMPTE": "COMPTE",
           "DN": "DN", "SID": "SID", "PERSO": "REF", "NOM": "NOM"},
    "en": {"EMAIL": "EMAIL", "TEL": "PHONE", "IBAN": "IBAN", "CARTE": "CARD", "SECU": "SSN",
           "IP": "IP_private", "IPPUB": "IP_PUB", "MAC": "MAC", "FQDN": "FQDN", "SECRET": "SECRET", "COMPTE": "ACCOUNT",
           "DN": "DN", "SID": "SID", "PERSO": "REF", "NOM": "NAME"},
}
# Préfixes reconnus à la restauration : ceux d'aujourd'hui, et « IP » des versions avant la 1.12.1
TOUS_PREFIXES = sorted({p for d in PREFIXES.values() for p in d.values()} | {"IP"}, key=len, reverse=True)


def _plat(texte):
    """Sans accents ni casse : « IP_privée », « IP_PRIVEE » et « ip_privee » désignent le même préfixe."""
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFD", texte) if unicodedata.category(c) != "Mn").casefold()


# Forme canonique de chaque préfixe, retrouvée quelle que soit la façon dont l'IA l'a réécrit
PREFIXE_CANONIQUE = {_plat(p): p for p in TOUS_PREFIXES}


def _alternative_prefixes():
    """Expression des préfixes : accents facultatifs (é ou e), « _ » éventuellement échappé par le Markdown."""
    morceaux = []
    for p in TOUS_PREFIXES:
        motif = ""
        for c in p:
            if c == "_":
                motif += r"(?:\\?_|-|\s)"
            elif _plat(c) != c.casefold():
                motif += f"[{c}{_plat(c)}]"
            else:
                motif += re.escape(c)
        morceaux.append(motif)
    return "|".join(morceaux)


def jeton_canonique(prefixe, numero):
    cle = re.sub(r"[\s-]+", "_", _plat(prefixe.replace(chr(92), "")))  # « IP privée », « IP-PRIVEE » -> ip_privee
    return f"[{PREFIXE_CANONIQUE.get(cle, prefixe.upper())}_{int(numero)}]"

# Types détectés automatiquement (les termes et les motifs personnalisés sont à part).
# Ordre d'affichage dans Options → Détection (deux colonnes) : IP locales et publiques côte à côte
TYPES_AUTO = ["EMAIL", "TEL", "IBAN", "CARTE", "SECU", "MAC", "IP", "IPPUB", "FQDN", "SECRET", "COMPTE", "DN", "SID"]
# Les deux types d'adresse IP sont trouvés par les mêmes expressions, puis classés selon la plage d'adresses
TYPES_IP = ("IP", "IPPUB")
# Types de la version 1.3 : les types ajoutés depuis sont activés pour les utilisateurs existants.
TYPES_V13 = ["EMAIL", "TEL", "IBAN", "CARTE", "SECU", "IP", "MAC", "FQDN"]

EXEMPLES = {
    "EMAIL": "jean.dupont@exemple.fr",
    "TEL": "06 12 34 56 78, +33 1 23 45 67 89",
    "IBAN": "FR76 3000 6000 0112 3456 7890 189",
    "CARTE": "4111 1111 1111 1111",
    "SECU": "1 85 05 78 006 084 36",
    "IP": "192.168.1.10, 10.0.0.5, fe80::1",
    "IPPUB": "185.220.101.47, 2a01:e0a:1f3::17",
    "MAC": "00:1A:2B:3C:4D:5E",
    "FQDN": "srv-paie01.acme.local, WORKSTATION5",
    "SECRET": "password=…, AKIA…, ghp_…, eyJ… (JWT), BEGIN PRIVATE KEY",
    "COMPTE": r"ACME\mlefevre, C:\Users\mlefevre, /home/mlefevre",
    "DN": "CN=Marc Lefevre,OU=Compta,DC=acme,DC=local",
    "SID": "S-1-5-21-3623811015-3361044348-30300820-1013",
}

# Un « domaine » qui se termine par une extension de fichier est un nom de fichier (rapport.pdf).
EXTENSIONS_FICHIERS = set(
    "pdf doc docx docm xls xlsx xlsm csv ppt pptx odt ods odp rtf txt md log ini cfg conf json xml yml "
    "yaml toml html htm css js ts jsx tsx py java cs cpp go rs rb php sql sh bat cmd ps1 vbs exe dll msi "
    "jar apk zip rar 7z gz tar iso png jpg jpeg gif bmp svg webp ico mp3 mp4 wav mov avi mkv eml msg "
    "tmp bak old dat db sqlite lnk git".split())

# Extensions de domaine acceptées : tous les codes pays (2 lettres), les plus courantes, et les suffixes
# internes. Sans cette liste, « spring.datasource.password » ou « java.lang.NullPointerException »
# seraient pris pour des noms de domaine.
EXTENSIONS_DOMAINE = set(
    "com net org info biz gov edu mil int arpa io ai app dev cloud tech online site xyz eu asia mobi name "
    "pro aero coop museum jobs travel tel cat paris bzh alsace corsica africa shop store blog news media "
    "email digital solutions services agency company group global network systems software security host "
    "page web website live space zone club"
    " local lan corp internal intranet intra home ad priv private localdomain test example invalid localhost "
    "domain office srv".split())

# Secrets : seule la valeur est masquée (groupe « v »), la clé reste lisible : password=[SECRET_1].
_CLES_SECRETES = (
    r"pass(?:word|wd|phrase)?|pwd|mdp|mot[ _-]?de[ _-]?passe|secret|client[_-]?secret"
    r"|(?:access|refresh|auth|api|bearer|sas|session)?[_-]?token|api[_-]?key|apikey|auth[_-]?key"
    r"|private[_-]?key|account[_-]?key|shared[_-]?access[_-]?key|community"
)
_VALEUR = r"""(?P<q>["'])?(?P<v>(?(q)[^"'\n]+|[^\s;,"'<>&]+))(?(q)(?P=q))"""
# Valeur d'un compte : sans parenthèses ni crochets, « (uid=0) » ne donne pas « 0) »
_VALEUR_COMPTE = r"""(?P<q>["'])?(?P<v>(?(q)[^"'\n]+|[^\s;,"'<>&()\[\]{}]+))(?(q)(?P=q))"""

# Une partie de DN : DC=… et C=… ne contiennent jamais d'espace (sinon DC=local avalerait la suite de la phrase)
_RDN = r"(?:(?:CN|OU|O|L|ST|UID)=[^,=\n+\"<>;()]+|(?:DC|C)=[\w-]+)"

# Ordre important : les motifs les plus spécifiques passent en premier.
MOTIFS = [
    ("SECRET", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("SECRET", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<v>[^\s@/]+)@", re.IGNORECASE)),
    ("SECRET", re.compile(r"\b(?:bearer|basic)\s+(?P<v>[A-Za-z0-9\-._~+/]{12,}=*)", re.IGNORECASE)),
    ("SECRET", re.compile(r"<(?P<k>password|pwd|secret|token|apikey|api_key)>(?P<v>[^<]+)</(?P=k)>",
                          re.IGNORECASE)),
    ("SECRET", re.compile(r"(?<![\w.(-])(?:[\w.-]*[_.-])?(?:" + _CLES_SECRETES + r")[\"']?[ \t]*[:=][ \t]*" + _VALEUR,
                          re.IGNORECASE)),
    ("SECRET", re.compile(
        r"(?<![\w-])(?:"
        r"(?:AKIA|ASIA)[0-9A-Z]{16}"                      # AWS
        r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}"  # GitHub
        r"|glpat-[A-Za-z0-9_-]{20,}"                      # GitLab
        r"|xox[abprs]-[A-Za-z0-9-]{10,}"                  # Slack
        r"|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"          # OpenAI, Anthropic
        r"|AIza[0-9A-Za-z_-]{35}"                         # Google
        r"|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"  # JWT
        r")(?![\w-])")),
    # net use \\srv\partage MOTDEPASSE /user:x  ou  net use \\srv\partage /user:x MOTDEPASSE (« * » = demandé)
    ("SECRET", re.compile(r"\bnet\s+use\b[^\n]*?/u(?:ser)?:\S+\s+(?P<v>[^\s/\"*][^\s\"]*)", re.IGNORECASE)),
    ("SECRET", re.compile(r"\bnet\s+use\s+(?:[A-Z]:\s+)?\\\\\S+\s+(?P<v>[^\s/\"*][^\s\"]*)\s+/u(?:ser)?:",
                          re.IGNORECASE)),
    # Compte dans une URL : https://deploy:motdepasse@serveur (le mot de passe est pris juste au-dessus)
    ("COMPTE", re.compile(r"\b[a-z][a-z0-9+.-]*://(?P<v>[^\s:/@]+)(?::[^\s@/]*)?@", re.IGNORECASE)),
    # DN : masqué partie par partie (voir _decomposer_dn), pour que l'IA reconnaisse la personne
    ("DN", re.compile(
        r"(?<![\w=])" + _RDN + r"(?:\s*,\s*" + _RDN + r")+",
        re.IGNORECASE)),
    ("SID", re.compile(r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b")),
    # Début de mot obligatoire : sinon une longue chaîne sans « @ » (base64 PowerShell) est relue à chaque caractère
    ("EMAIL", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("IBAN", re.compile(r"(?<![\w-])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?(?![\w-])")),
    ("SECU", re.compile(
        r"(?<![\d\w.])[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB])"
        r" ?\d{3} ?\d{3}(?: ?\d{2})?(?![\d\w.])")),
    ("CARTE", re.compile(r"(?<![\w-])(?:\d{4}[ -]?){3}\d{4}(?![\w-])")),
    ("TEL", re.compile(
        r"(?<![\w+.:/-])(?:(?:\+|00)33 ?(?:\(0\) ?)?|0)[1-9](?P<sep>[ .-]?)\d{2}(?:(?P=sep)\d{2}){3}(?![\w.:-])"  # France
        r"|(?<![\w+])\+[1-9]\d{0,2}[ .-]?\d{1,4}(?:[ .-]?\d{2,4}){2,4}(?![\w.])"   # international
    )),
    # Compte d'ordinateur (WORKSTATION5$, svc_ADFS$) : le nom de la machine est masqué, le « $ » reste
    ("FQDN", re.compile(r"(?<![\w$\\%-])(?P<v>(?=[\w-]*[A-Za-z])[A-Za-z0-9][\w-]{1,19})\$(?![\w$])")),
    # En-tête syslog : « Nov 12 08:01:02 srv-web01 sshd[123]: » (et horodatage ISO de rsyslog)
    ("FQDN", re.compile(
        r"(?m)^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)"
        r" (?P<v>[A-Za-z0-9][\w.-]*) (?=[\w./()-]+(?:\[\d+\])?:)")),
    # ipconfig /all, systeminfo, hostnamectl, auditd : nom de la machine
    ("FQDN", re.compile(
        r"(?im)^[ \t]*(?:Host Name|Nom de l'h[ôo]te|Static hostname|Transient hostname|Primary Dns Suffix|"
        r"Suffixe DNS principal|Domain|Domaine|Logon Server|Serveur d'ouverture de session)"
        r"[ \t.]*:[ \t]*\\{0,2}(?P<v>[A-Za-z0-9][\w.-]*)[ \t]*$")),
    # Transcript PowerShell : « Machine: PC-0815 (Microsoft Windows NT …) »
    ("FQDN", re.compile(r"(?im)^Machine:[ \t]*(?P<v>[A-Za-z0-9][\w.-]*)(?=[ \t]*(?:\(|$))")),
    # Serveur d'un chemin réseau : \\fs01\partage
    ("FQDN", re.compile(r"(?<![\w\\])\\\\(?P<v>[A-Za-z0-9][\w-]{0,62})(?=\\)")),
    ("FQDN", re.compile(
        r"(?<![\w.-])\"?(?:host[_-]?name|host|computer(?:[_-]?name)?|workstation|machine[_-]?name|device[_-]?name|"
        r"client[_-]?name|src[_-]?name|dst[_-]?name|dev[_-]?name)\"?[ \t]*[:=][ \t]*\"?(?P<v>[A-Za-z0-9][\w.-]*)",
        re.IGNORECASE)),
    # Entra ID (Azure AD) : nom de l'appareil dans deviceDetail
    ("FQDN", re.compile(r'"deviceDetail"\s*:\s*\{[^{}]*?"displayName"\s*:\s*"(?P<v>[^"]+)"')),
    # DNS Windows (journal de débogage) : (5)rds01(8)vallorie(5)local(0)
    ("FQDN", re.compile(r"(?:\(\d{1,2}\)[\w-]+){2,}\(0\)")),
    # DHCP Windows : adresse MAC sans séparateurs dans le journal CSV
    ("MAC", re.compile(r"(?m)^\d{2},\d\d/\d\d/\d\d,\d\d:\d\d:\d\d,[^,\n]*,[^,\n]*,[^,\n]*,(?P<v>[0-9A-Fa-f]{12}),")),
    # Événements Windows tels qu'affichés (Observateur d'événements, SIEM) : un champ par ligne
    ("FQDN", re.compile(
        r"(?im)^[ \t]*(?:Account Domain|Domain Name|Domaine du compte|Nom de domaine|Workstation Name|"
        r"Source Workstation|Nom de la station de travail|Station de travail source|Client Name|"
        r"(?:Caller )?Computer(?: Name)?|Supplied Realm Name|Target Domain|Target Server Name|Nom du serveur cible)"
        r"[ \t]*:[ \t]*(?P<v>[A-Za-z0-9][\w.-]*)[ \t]*$")),
    ("COMPTE", re.compile(
        r"(?im)^[ \t]*(?:Account Name|Nom du compte|Logon Account|Compte d'ouverture de session|User Name|"
        r"Nom d'utilisateur|SAM Account Name|New Account Name|Old Account Name|Target User Name|"
        r"Account For Which Logon Failed|Client User Name)[ \t]*:[ \t]*(?P<v>[^\s\\-][^\t\r\n]*?)[ \t]*$")),
    # Comptes : DOMAINE\utilisateur (domaine NetBIOS en majuscules), et l'utilisateur dans un chemin de profil
    ("COMPTE", re.compile(r"(?<![\w\\/.-])(?P<d>[A-Z][A-Z0-9-]{1,14})\\[A-Za-z0-9][\w.$-]{1,63}(?![\w\\])")),
    ("COMPTE", re.compile(
        r"\b[a-z]:\\(?:users|documents and settings)\\(?P<v>[^\\/\n:*?\"<>|]+(?=\\)|[^\\/\s:*?\"<>|]+)",
        re.IGNORECASE)),
    ("COMPTE", re.compile(r"(?<![\w./-])/(?:home|Users)/(?P<v>[A-Za-z0-9._-]+)")),
    ("COMPTE", re.compile(
        r"(?<![\w.-])(?:user[ _-]?id|uid|user(?:[_-]?name)?|login|acct|account(?:[_-]?(?:name|id))?|samaccountname"
        r"|principal[_-]?id|recipient[_-]?account[_-]?id|owner[_-]?id)"
        r"[\"']?[ \t]*[:=][ \t]*" + _VALEUR_COMPTE, re.IGNORECASE)),
    # AWS : numéro de compte et utilisateur ou rôle dans un ARN (arn:aws:iam::123456789012:user/pedro)
    ("COMPTE", re.compile(r"\barn:aws[\w-]*:[\w-]*:[\w-]*:(?P<v>\d{12}):")),
    ("COMPTE", re.compile(r"\barn:aws[\w-]*:(?:iam|sts)::\d{12}:(?:user|role|group|assumed-role)/"
                          r"(?:[\w+=,.@-]+/)*(?P<v>[\w+=,.@-]+)")),
    # Kerberos (Zeek, klist) : « stevie.marie/PANDALAB.COM » ; les classes de service (krbtgt/, ldap/) restent
    ("COMPTE", re.compile(r"(?<![\w./\\$-])(?P<v>[\w.-]+)/(?=(?:[A-Z0-9-]+\.)+[A-Z]{2,}(?![\w.]))")),
    # Comptes dans les journaux : SQL Server, sshd, PAM, sudo, net use /user:x
    ("COMPTE", re.compile(r"\bfor (?:invalid |illegal )?user '(?P<v>[^'\s\\]+)'", re.IGNORECASE)),
    ("COMPTE", re.compile(r"\bfor (?:invalid |illegal )?user (?P<v>[\w.$-]+)(?= from\b)")),
    ("COMPTE", re.compile(r"\b(?:Accepted|Failed) [\w/-]+ for (?P<v>[\w.$-]+) from\b")),
    ("COMPTE", re.compile(r"\bsession (?:opened|closed) for user (?P<v>[\w.$-]+)")),
    ("COMPTE", re.compile(r"\bsudo(?:\[\d+\])?:\s+(?P<v>[\w.$-]+) : ")),
    # Cisco ASA (« User <jdupont> »), Squid (colonne utilisateur avant HIER_…)
    ("COMPTE", re.compile(r"\b[Uu]ser <(?P<v>[^<>\s]+)>")),
    ("COMPTE", re.compile(r"(?m)^\d{9,10}\.\d{3}\s+\d+ \S+ [A-Z_]+/\d{3} \d+ [A-Z]+ \S+ (?P<v>[^\s-]\S*) [A-Z_]+/")),
    ("COMPTE", re.compile(r"\b(?:[Ss]ession \d+|[Ss]lice) of user (?P<v>[\w.$-]+?)\.?(?=\s|$)")),
    ("COMPTE", re.compile(r"\bpassword (?:changed|expired) for (?P<v>[\w.$-]+)")),
    ("COMPTE", re.compile(r"\bby (?P<v>[\w.$-]+)\(uid=\d+\)")),
    ("COMPTE", re.compile(r"\b(?:new user: name|delete user|removed user|changed user)[ =']+(?P<v>[\w.$-]+)")),
    # Journal d'accès Apache / nginx : « 10.1.2.3 - jdupont [12/Nov/2026:… »
    ("COMPTE", re.compile(r"(?m)^\S+ \S+ (?P<v>[^\s\[-][^\s\[]*) \[\d{2}/\w{3}/\d{4}:")),
    # net user : la commande et sa sortie
    ("COMPTE", re.compile(r"(?i)\bnet\s+user\s+(?P<v>(?!/)[^\s/\"]+)")),
    ("COMPTE", re.compile(r"(?im)^(?:User name|Nom d'utilisateur)[ \t]{2,}(?P<v>\S+)[ \t]*$")),
    ("COMPTE", re.compile(r"\bnet\s+use\b[^\n]*?/u(?:ser)?:(?P<v>[^\s\\\"]+)(?=[\s\"]|$)", re.IGNORECASE)),
    ("IP", re.compile(r"(?<![\w.~])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")),
    ("IP", re.compile(
        r"(?<![\w:.])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"           # IPv6 complète
        r"|(?:[0-9a-f]{1,4}:){1,6}(?::[0-9a-f]{1,4}){1,6}"              # abrégée : 2a01:e0a::17
        r"|(?:[0-9a-f]{1,4}:){1,7}:|::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})"
        r"(?:%[\w.]+)?(?![\w:])", re.IGNORECASE)),
    ("MAC", re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")),
    ("FQDN", re.compile(
        r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?P<tld>[a-z]{2,63})(?![\w-]|\.\w)",
        re.IGNORECASE)),
]

# Titre de chaque expression, dans l'ordre de MOTIFS, pour la fenêtre « Voir l'expression » des Options
DESCRIPTIONS = [
    ("Clé privée (BEGIN … PRIVATE KEY)", "Private key (BEGIN … PRIVATE KEY)"),
    ("Mot de passe dans une URL (https://user:motdepasse@…)", "Password in a URL (https://user:password@…)"),
    ("Jeton après Bearer ou Basic", "Token after Bearer or Basic"),
    ("Balise XML <password>, <token>…", "XML tag <password>, <token>…"),
    ("Clé = valeur : password=, pwd:, api_key=, token=…", "Key = value: password=, pwd:, api_key=, token=…"),
    ("Clés connues : AWS, GitHub, GitLab, Slack, OpenAI, Google, JWT", "Known keys: AWS, GitHub, GitLab, Slack, OpenAI, Google, JWT"),
    ("Mot de passe de net use, après /user:", "net use password, after /user:"),
    ("Mot de passe de net use, avant /user:", "net use password, before /user:"),
    ("Utilisateur dans une URL (https://user@…)", "User in a URL (https://user@…)"),
    ("DN Active Directory / LDAP", "Active Directory / LDAP DN"),
    ("SID de domaine Windows (S-1-5-21-…)", "Windows domain SID (S-1-5-21-…)"),
    ("Adresse e-mail", "Email address"),
    ("IBAN (longueur du pays vérifiée)", "IBAN (country length checked)"),
    ("N° de sécurité sociale (NIR)", "Social security number (French NIR)"),
    ("Carte bancaire (16 chiffres)", "Credit card (16 digits)"),
    ("Téléphone français ou international", "French or international phone number"),
    ("Compte d'ordinateur (PC-0815$) : le nom de la machine", "Computer account (PC-0815$): the machine name"),
    ("En-tête syslog : la machine après l'heure", "Syslog header: the machine after the time"),
    ("ipconfig /all, systeminfo, hostnamectl : Host Name, Domain…", "ipconfig /all, systeminfo, hostnamectl: Host Name, Domain…"),
    ("Transcript PowerShell : Machine:", "PowerShell transcript: Machine:"),
    ("Serveur d'un chemin réseau (\\\\fs01\\partage)", "Server in a network path (\\\\fs01\\share)"),
    ("Clé = machine : hostname=, srcname=, deviceName…", "Key = machine: hostname=, srcname=, deviceName…"),
    ("Entra ID : appareil dans deviceDetail", "Entra ID: device in deviceDetail"),
    ("DNS Windows : (5)srv01(4)acme(5)local(0)", "Windows DNS: (5)srv01(4)acme(5)local(0)"),
    ("DHCP Windows : adresse MAC sans séparateurs", "Windows DHCP: MAC address without separators"),
    ("Événement Windows : domaine et poste (Account Domain, Workstation Name…)",
     "Windows event: domain and workstation (Account Domain, Workstation Name…)"),
    ("Événement Windows : compte (Account Name, Nom du compte…)", "Windows event: account (Account Name…)"),
    ("DOMAINE\\utilisateur (domaine en majuscules)", "DOMAIN\\user (upper-case domain)"),
    ("Profil Windows : C:\\Users\\…", "Windows profile: C:\\Users\\…"),
    ("Profil Linux / macOS : /home/…, /Users/…", "Linux / macOS profile: /home/…, /Users/…"),
    ("Clé = compte : user=, login=, uid=, acct=, accountId…", "Key = account: user=, login=, uid=, acct=, accountId…"),
    ("AWS : numéro de compte dans un ARN", "AWS: account number in an ARN"),
    ("AWS : utilisateur ou rôle dans un ARN", "AWS: user or role in an ARN"),
    ("Kerberos : utilisateur/ROYAUME (Zeek, klist)", "Kerberos: user/REALM (Zeek, klist)"),
    ("SQL Server : for user '…'", "SQL Server: for user '…'"),
    ("SSH : for invalid user … from", "SSH: for invalid user … from"),
    ("SSH : Accepted / Failed … for … from", "SSH: Accepted / Failed … for … from"),
    ("PAM : session opened for user …", "PAM: session opened for user …"),
    ("sudo : l'utilisateur qui lance la commande", "sudo: the user running the command"),
    ("Cisco ASA : User <…>", "Cisco ASA: User <…>"),
    ("Squid : colonne utilisateur", "Squid: user column"),
    ("systemd : Session … of user …", "systemd: Session … of user …"),
    ("passwd : password changed for …", "passwd: password changed for …"),
    ("su : by …(uid=…)", "su: by …(uid=…)"),
    ("useradd / userdel : new user: name=…", "useradd / userdel: new user: name=…"),
    ("Journal d'accès Apache / nginx : utilisateur authentifié", "Apache / nginx access log: authenticated user"),
    ("net user … (commande)", "net user … (command)"),
    ("net user : User name …", "net user: User name …"),
    ("net use : utilisateur après /user:", "net use: user after /user:"),
    ("Adresse IPv4", "IPv4 address"),
    ("Adresse IPv6", "IPv6 address"),
    ("Adresse MAC (00:1A:2B:… ou 00-1A-2B-…)", "MAC address (00:1A:2B:… or 00-1A-2B-…)"),
    ("Nom de domaine (srv01.acme.local, intranet.acme.fr)", "Domain name (srv01.acme.local, intranet.acme.fr)"),
]
assert len(DESCRIPTIONS) == len(MOTIFS), "une description par expression"

DOMAINES_SYSTEME = {"BUILTIN", "NT", "AUTHORITY", "SERVICE", "APPPOOL", "WORKGROUP", "HKLM", "HKCU", "HKCR",
                    "HKU", "HKCC", "SYSTEM", "LOCAL",
                    # Identifiants de périphériques Windows : PCI\VEN_8086, USB\VID_80EE, SCSI\DISK…
                    "PCI", "HDAUDIO", "HID", "ACPI", "USB", "USBSTOR", "SCSI", "SWD", "ROOT", "STORAGE", "DISPLAY",
                    "BTHENUM", "BTH", "IDE", "PCIIDE", "UMB", "SW", "MONITOR", "HTREE", "NDIS", "BTHLE", "BTHLEDEVICE",
                    "INTELAUDIO", "TS_USB_HUB_ENUMERATOR", "VMBUS", "WPDBUSENUM", "MMDEVAPI", "UEFI"}
PROFILS_GENERIQUES = {"public", "default", "default user", "all users", "shared", "guest"}
# Valeurs qui ne sont pas des comptes : champs vides, booléens, comptes intégrés de Windows
COMPTES_NEUTRES = {"-", "?", "(unknown)", "unset", "self", "anonymous_principal", "no", "yes", "true", "false", "none", "null", "n/a", "na", "unknown", "nt", "system",
                   "local service", "network service", "localsystem", "anonymous logon", "nt authority",
                   "service local", "service réseau", "système", "ouverture de session anonyme", "%%1843"}
MACHINES_NEUTRES = {"?", "(NONE)", "LOCALHOST.LOCALDOMAIN", "UBUNTU", "DEBIAN", "KALI", "WORKGROUP", "BUILTIN", "NT AUTHORITY", "NT", "LOCALHOST", "MSHOME", "ADMIN", "IPC", "PRINT",
                    "WINDOW MANAGER", "FONT DRIVER HOST", "NT SERVICE", "-"}
# Longueur des IBAN par pays (un IBAN de la mauvaise longueur n'en est pas un : empreinte MD5, identifiant…)
LONGUEURS_IBAN = dict(
    (c, int(n)) for c, n in (x.split(":") for x in (
        "AD:24 AE:23 AL:28 AT:20 AZ:28 BA:20 BE:16 BG:22 BH:22 BR:29 BY:28 CH:21 CR:22 CY:28 CZ:24 DE:22 DK:18 "
        "DO:28 EE:20 EG:29 ES:24 FI:18 FO:18 FR:27 GB:22 GE:22 GI:23 GL:18 GR:27 GT:28 HR:21 HU:28 IE:22 IL:23 "
        "IQ:23 IS:26 IT:27 JO:30 KW:30 KZ:20 LB:28 LC:32 LI:21 LT:20 LU:20 LV:21 MC:27 MD:24 ME:22 MK:19 MR:27 "
        "MT:31 MU:30 NL:18 NO:15 PK:24 PL:28 PS:29 PT:25 QA:29 RO:24 RS:22 SA:24 SC:31 SE:24 SI:19 SK:24 SM:27 "
        "ST:25 SV:28 TL:23 TN:24 TR:26 UA:29 VA:22 VG:24 XK:20").split()))
# Codes pays utilisés comme extensions de domaine (sans cette liste, « subject.OU » passait pour un domaine)
CODES_PAYS = set(
    "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz "
    "ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk "
    "fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq "
    "ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh "
    "mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk "
    "pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st sv sx sy sz tc "
    "td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw".split())
# Premier niveau d'un identifiant à l'envers (com.apple.xpc, org.mozilla…) : ce n'est pas un nom de machine
SERVICES_SPN = {"krbtgt", "ldap", "cifs", "host", "http", "https", "mssqlsvc", "rpcss", "dns", "gc", "wsman",
                "termsrv", "restrictedkrbhost", "kadmin", "nfs", "smtp", "imap", "pop", "ftp", "exchangemdb",
                "exchangerfr", "exchangeab", "dhcp", "time", "msomhsvc", "msoledbsql", "postgres", "mysql"}
# Mots qui, juste avant un numéro, confirment qu'il s'agit bien d'une carte ou d'un n° de sécurité sociale
_CONTEXTE = {
    "CARTE": re.compile(r"(?i)(?:carte|card|\bcb\b|visa|mastercard|master card|amex|\bpan\b|cr[ée]dit)"),
    "SECU": re.compile(r"(?i)(?:s[ée]cu|s[ée]curit[ée] sociale|\bnir\b|insee|\bssn\b|social security|n° ss|num_ss)"),
}
DEBUTS_INVERSES = {"com", "org", "net", "edu", "gov", "io", "fr", "de", "uk", "eu", "ch", "be", "nl", "jp"}


_PLAGES_LOCALES = [ipaddress.ip_network(r) for r in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "fc00::/7", "fe80::/10", "ff00::/8")]


def type_ip(valeur):
    """« IP » pour une adresse locale (privée, CGNAT, lien local, multicast, documentation), « IPPUB » sinon."""
    try:
        adresse = ipaddress.ip_address(valeur.split("%")[0])
    except ValueError:
        return "IP"
    if adresse.version == 6 and adresse.ipv4_mapped:
        adresse = adresse.ipv4_mapped
    return "IP" if any(adresse in plage for plage in _PLAGES_LOCALES if plage.version == adresse.version) else "IPPUB"


def _luhn(chiffres):
    total = 0
    for i, c in enumerate(reversed(chiffres)):
        n = int(c) * (2 if i % 2 else 1)
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def _iban_valide(compact):
    reorganise = compact[4:] + compact[:4]
    try:
        return int("".join(str(int(c, 36)) for c in reorganise)) % 97 == 1
    except ValueError:
        return False


def _nir_valide(compact):
    corps = compact[:13].upper().replace("2A", "19").replace("2B", "18")
    return corps.isdigit() and 97 - int(corps) % 97 == int(compact[13:])
# Bouclage et adresses non attribuées : rien à cacher, et l'IA comprend mieux « 127.0.0.1 » qu'un jeton
IP_NEUTRES = {"0.0.0.0", "::", "::1", "255.255.255.255"}
# Types propagés à l'identique (majuscules comprises) : un mot de passe, ou un compte comme « root » ou
# « Security » qui ne doit pas masquer « ROOT LOGIN » ou « PCI Root Bridge »
EXACTS = ("SECRET", "COMPTE")


def _accepte(type_, m, valeur):
    if type_ == "SECRET":
        if re.match(r"(?:[/~]|[A-Za-z]:\\)", valeur):
            return False  # PWD=/home/x (dossier courant dans sudo) ou un chemin : pas un mot de passe
        if valeur.lower() in COMPTES_NEUTRES or re.match(r"(?:com|org|net)\.[a-z]+\.", valeur):
            return False  # « Elevated Token: No », identifiant macOS (com.apple.xpc…)
        if re.match(r"[A-Z]\w*\{", valeur):
            return False  # objet Java affiché : token=Token{a64f992}
    if type_ == "IP":
        try:
            adresse = ipaddress.ip_address(valeur.split("%")[0])
        except ValueError:
            return False
        if adresse.is_loopback or adresse.is_unspecified or str(adresse) in IP_NEUTRES:
            return False
        if adresse.version == 4 and valeur.startswith("0."):
            return False
        avant = m.string[max(0, m.start() - 12):m.start()]
        if re.search(r"\b(?:version|ver\.?|v)[ =:]*$", avant, re.IGNORECASE):
            return False  # « wcp.dll version 0.0.0.6 », « Version=4.0.0.0 »
        if ":" in valeur:  # IPv6 : au moins un chiffre (pas « dead:beef: »)
            return any(c.isdigit() for c in valeur)
        return True
    if type_ == "FQDN":
        if "tld" not in m.re.groupindex:  # nom de machine ou de domaine NetBIOS (champ d'événement, NOM$)
            return valeur.upper() not in MACHINES_NEUTRES and not re.fullmatch(r"(?:DWM|UMFD)-\d+", valeur)
        tld = m.group("tld")
        etiquettes = valeur.split(".")
        if tld.lower() in EXTENSIONS_FICHIERS or (len(tld) == 2 and tld.lower() not in CODES_PAYS):
            return False
        if len(tld) > 2 and tld.lower() not in EXTENSIONS_DOMAINE:
            return False
        if re.fullmatch(r"[A-Z][a-z]+[A-Za-z]*", tld) and tld != tld.capitalize().upper():
            return False  # espace de noms .NET : System.Security, Microsoft.PowerShell.Security
        if len(etiquettes) >= 3 and etiquettes[0].lower() in DEBUTS_INVERSES:
            return False  # identifiant à l'envers : com.apple.private.ac
        if re.search(r"(?i)\.(?:exe|dll|sys)-[0-9a-f]{8}\.pf$", valeur):
            return False  # fichier Prefetch : REG.EXE-E7E8BD26.pf
        if len(etiquettes) == 2 and tld.lower() == "app" and etiquettes[0][:1].isupper():
            return False  # application macOS : Weather.app
        return True
    if type_ == "COMPTE":
        domaine = m.groupdict().get("d")
        if domaine and (domaine in DOMAINES_SYSTEME or domaine.startswith("HKEY")):
            return False
        propre = valeur.strip().lower()
        if propre in PROFILS_GENERIQUES or propre in COMPTES_NEUTRES or (propre.isdigit() and len(propre) < 6):
            return False  # uid=0, uid=1000 ; un n° de compte AWS (12 chiffres) reste masqué
        if propre in SERVICES_SPN and m.string[m.end("v"):m.end("v") + 1] == "/":
            return False  # krbtgt/DOMAINE.LOCAL, ldap/DC01… : classe de service, pas un utilisateur
        return not re.fullmatch(r"(?:dwm|umfd)-\d+", propre)
    if type_ in ("CARTE", "IBAN", "SECU"):
        compact = re.sub(r"[ -]", "", valeur)
        saisi = compact != valeur  # écrit avec ses espaces, comme dans un mail ou un ticket
        avant = m.string[max(0, m.start() - 60):m.start()]
        if type_ == "CARTE":
            if compact[0] not in "23456":
                return False
            groupes_reguliers = re.fullmatch(r"\d{4}([ -])\d{4}\1\d{4}\1\d{4}", valeur)
            # Luhn valide, ou écrit comme une carte (4 x 4) avec « carte », « CB », « Visa »… juste avant
            return _luhn(compact) or bool(saisi and groupes_reguliers and _CONTEXTE["CARTE"].search(avant))
        if type_ == "IBAN":
            if LONGUEURS_IBAN.get(compact[:2]) != len(compact):
                return False
            return saisi or _iban_valide(compact)
        if len(compact) == 15 and _nir_valide(compact):
            return True
        if re.fullmatch(r"[12] \d{2} (?:0[1-9]|1[0-2]|[2-9]\d) (?:\d{2}|2[AB]) \d{3} \d{3}(?: \d{2})?", valeur):
            return True  # présentation officielle du NIR (1 85 05 78 006 084 36) : sans ambiguïté
        # Sinon, clé fausse ou absente : seulement si « sécu », « NIR »… précède (des nombres quelconques passeraient)
        return saisi and len(compact) in (13, 15) and bool(_CONTEXTE["SECU"].search(avant))
    return True


_COMPOSANT_DN = re.compile(r"(?P<cle>CN|OU|O|L|ST|UID)=(?P<val>[^,=\n+\"<>;()]+)|(?P<cle2>DC|C)=(?P<val2>[\w-]+)",
                           re.IGNORECASE)


def _decomposer_dn(m, termes):
    """Parties à masquer d'un DN : (début, fin, type, valeur).

    CN=Sophie Bernard,OU=Comptabilite,DC=acme,DC=local devient CN=[NOM_3],OU=Comptabilite,[DN_1] :
    le nom (CN, UID) reprend le jeton du terme ou du compte s'il est connu, la suite DC=… (le domaine)
    et O=… sont masquées, l'OU et la localisation restent lisibles.
    """
    texte, base = m.string, m.start()
    sortie, domaine = [], None

    def fermer():
        if domaine:
            sortie.append((domaine[0], domaine[1], "DN", texte[domaine[0]:domaine[1]]))

    for c in _COMPOSANT_DN.finditer(m.group(0)):
        groupe = "val" if c.group("cle") else "val2"
        cle = (c.group("cle") or c.group("cle2")).upper()
        d, f = base + c.start(groupe), base + c.end(groupe)
        while f > d and texte[f - 1].isspace():
            f -= 1
        if cle == "DC":
            domaine = [domaine[0], f] if domaine else [base + c.start(), f]
            continue
        fermer()
        domaine = None
        valeur = texte[d:f]
        if cle in ("CN", "UID"):
            sortie.append((d, f, "NOM" if " ".join(valeur.split()).casefold() in termes else "COMPTE", valeur))
        elif cle == "O":
            sortie.append((d, f, "DN", valeur))
    fermer()
    return sortie


def _plage(m):
    """Partie à masquer : le groupe « v » s'il existe, sinon tout ; sans espaces en bout."""
    debut, fin = m.span("v") if "v" in m.re.groupindex and m.group("v") else m.span()
    texte = m.string
    while fin > debut and texte[fin - 1].isspace():
        fin -= 1
    return debut, fin


def expressions(type_, langue="fr"):
    """Expressions appliquées pour un type : [(motif, insensible_a_la_casse, titre)], pour les afficher."""
    i = 0 if langue == "fr" else 1
    type_ = "IP" if type_ in TYPES_IP else type_
    return [(m.pattern, bool(m.flags & re.IGNORECASE), d[i]) for (t, m), d in zip(MOTIFS, DESCRIPTIONS) if t == type_]


def normaliser_etiquette(texte):
    """Jeton personnalisé saisi par l'utilisateur -> nom de jeton : « Client principal » -> CLIENT_PRINCIPAL."""
    import unicodedata
    texte = unicodedata.normalize("NFKD", texte.strip().strip("[]")).encode("ascii", "ignore").decode()
    return re.sub(r"_+", "_", re.sub(r"[^A-Z0-9]", "_", texte.upper())).strip("_")[:40]


def etiquette_reservee(nom):
    """Un jeton personnalisé ne doit pas ressembler à un jeton automatique ([NOM_3], [IP_1]…)."""
    return bool(re.fullmatch(r"(?:" + _alternative_prefixes() + r")_\d+", nom, re.IGNORECASE))


def compiler_motif(motif):
    """Motif personnalisé (expression régulière), insensible à la casse. Lève re.error s'il est invalide.

    La syntaxe .NET / PowerShell des groupes nommés, (?<v>…), est acceptée comme (?P<v>…).
    """
    motif = re.sub(r"\(\?<(?![=!])", "(?P<", motif)
    rx = re.compile(motif, re.IGNORECASE)
    if rx.match(""):
        raise re.error("le motif ne doit pas accepter un texte vide")
    return rx


# Tolère les variantes qu'une IA peut produire : [nom_1], [ NOM_1 ], [NOM 1], \[NOM\_1\] (Markdown)…
JETON_RE = re.compile(
    r"\\?\[\s*(" + _alternative_prefixes() + r")\s*(?:\\?_|-|\s)?\s*(\d+)\s*\\?\]",
    re.IGNORECASE,
)


_VARIANTES = {"a": "aàâäáãå", "e": "eéèêë", "i": "iîïíì", "o": "oôöóòõ", "u": "uùûüú", "c": "cç", "y": "yÿý", "n": "nñ"}


def _sans_accents(texte):
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFKD", texte) if not unicodedata.combining(c))


def _motif_mot(mot):
    """Mot d'un terme, insensible aux accents : « Lefèvre » trouve aussi « Lefevre » et « LEFEVRE »."""
    morceaux = []
    for c in mot:
        base = _sans_accents(c).lower()
        morceaux.append(f"[{_VARIANTES[base]}]" if base in _VARIANTES else re.escape(c))
    return "".join(morceaux)


def _cle(valeur, type_=None):
    """Clé de comparaison : les différentes écritures d'une même donnée donnent le même jeton."""
    if type_ == "TEL":
        compact = re.sub(r"[\s.()-]", "", valeur)
        chiffres = re.sub(r"\D", "", valeur)
        if compact.startswith("+33"):
            chiffres = chiffres[2:]
        elif compact.startswith("0033"):
            chiffres = chiffres[4:]
        else:
            return ("+" if compact.startswith("+") else "") + chiffres
        return "0" + chiffres.lstrip("0")  # +33 6…, 0033 6…, +33 (0)6… → 06…
    if type_ == "SECRET":
        return valeur  # un secret est comparé à l'identique
    if type_ in ("IBAN", "CARTE", "SECU"):
        return re.sub(r"[\s.-]", "", valeur).upper()
    if type_ == "MAC":
        return re.sub(r"[:-]", "", valeur).upper()
    if type_ == "NOM":
        return _sans_accents(" ".join(valeur.split())).casefold()
    return " ".join(valeur.split()).casefold()


@dataclass
class Resultat:
    texte: str
    spans_source: list = field(default_factory=list)   # (début, fin, jeton) dans le texte d'entrée
    spans_sortie: list = field(default_factory=list)   # (début, fin, jeton) dans le texte produit
    compte: Counter = field(default_factory=Counter)   # jeton -> occurrences remplacées
    ignores: Counter = field(default_factory=Counter)  # jeton -> occurrences laissées en clair
    ordre: list = field(default_factory=list)          # jetons dans l'ordre d'apparition
    inconnus: list = field(default_factory=list)       # (début, fin, texte) jetons sans correspondance


class Anonymiseur:
    def __init__(self, langue="fr"):
        self.langue = langue
        self.reinitialiser()

    def reinitialiser(self):
        self.valide = {}      # jeton -> (type, valeur) : déjà envoyé à l'IA
        self.index = {}       # (type, clé) -> jeton
        self.exclus = set()   # jetons que l'utilisateur ne veut plus masquer
        self._apercu = {}     # jetons du texte en cours, pas encore copiés
        self._apercu_index = {}
        self._compteurs = Counter()  # type -> nombre de jetons déjà créés (validés + aperçu)
        self.etiquettes = {}  # clé d'un terme permanent -> jeton personnalisé (sans crochets)
        self.a_annoncer = {}  # ancien jeton déjà envoyé -> nouveau jeton, à signaler à l'IA à la copie
        self._renommages = {}

    # --- jetons -----------------------------------------------------------
    def _jeton(self, type_, valeur):
        cle = (type_, _cle(valeur, type_))
        existant = self.index.get(cle) or self._apercu_index.get(cle)
        if not existant and type_ in TYPES_IP:  # IP envoyée avant la distinction locale / publique
            autre = ("IPPUB" if type_ == "IP" else "IP", cle[1])
            existant = self.index.get(autre) or self._apercu_index.get(autre)
        perso = None
        if type_ == "NOM":  # clés des jetons personnalisés comparées sans accents, comme les termes
            perso = next((j for t, j in self.etiquettes.items() if _cle(t, "NOM") == cle[1] and j), None)
        if perso:
            jeton = f"[{perso}]"
            if existant and existant != jeton and existant in self.valide:
                self._renommages[existant] = jeton  # l'IA connaît l'ancien jeton : il faudra la prévenir
            if jeton not in self.valide:
                self._apercu[jeton] = (type_, valeur)
            self._apercu_index[cle] = jeton
            return jeton
        if existant:
            return existant
        prefixe = PREFIXES.get(self.langue, PREFIXES["fr"])[type_]
        while True:  # un numéro déjà écrit tel quel dans le texte (« [IP_1] » d'un modèle) est sauté
            self._compteurs[type_] += 1
            jeton = f"[{prefixe}_{self._compteurs[type_]}]"
            if jeton not in self._reserves:
                break
        self._apercu[jeton] = (type_, valeur)
        self._apercu_index[cle] = jeton
        return jeton

    def info(self, jeton):
        return self.valide.get(jeton) or self._apercu.get(jeton)

    def jetons(self):
        """Tous les jetons de la conversation, dans l'ordre de création."""
        return list(self.valide) + [j for j in self._apercu if j not in self.valide]

    def etat(self):
        return {"valide": {j: list(v) for j, v in self.valide.items()}, "exclus": sorted(self.exclus),
                "index": [[t, c, j] for (t, c), j in self.index.items()], "a_annoncer": self.a_annoncer}

    def charger_etat(self, etat):
        self.reinitialiser()
        for jeton, (type_, valeur) in etat.get("valide", {}).items():
            self.valide[jeton] = (type_, valeur)
            self.index[(type_, _cle(valeur, type_))] = jeton
        # Index enregistré : après un renommage, la valeur pointe vers le nouveau jeton, pas l'ancien
        for type_, cle, jeton in etat.get("index", []):
            if jeton in self.valide:
                # clé recalculée : celles des termes sont sans accents depuis la v1.10.2
                self.index[(type_, _cle(cle, type_) if type_ == "NOM" else cle)] = jeton
        self.a_annoncer = {a: n for a, n in etat.get("a_annoncer", {}).items() if a in self.valide}
        self.exclus = set(etat.get("exclus", [])) & set(self.valide)
        self._compteurs = Counter(t for t, _ in self.valide.values())

    def renommages(self):
        """Changements de jeton à signaler à l'IA : ceux déjà validés et ceux du texte en cours."""
        return {**self.a_annoncer, **self._renommages}

    def renommages_annonces(self):
        self.a_annoncer = {}

    def valider(self):
        """Fige les jetons du texte en cours (à appeler quand il est copié pour l'IA)."""
        self.valide.update(self._apercu)
        self.index.update(self._apercu_index)
        self.a_annoncer.update(self._renommages)
        self._apercu, self._apercu_index, self._renommages = {}, {}, {}
        self._compteurs = Counter(t for t, _ in self.valide.values())

    def reinclure(self, type_, valeur):
        cle = (type_, _cle(valeur, type_))
        jeton = self.index.get(cle) or self._apercu_index.get(cle)
        self.exclus.discard(jeton)

    # --- traitements ------------------------------------------------------
    def anonymiser(self, texte, termes=(), types=None, motifs=()):
        """types : types détectés automatiquement (None = tous) ; motifs : expressions personnalisées."""
        # Les jetons d'un aperçu non copié sont recalculés à chaque fois : taper
        # « jean@ex.f » puis « jean@ex.fr » ne crée pas deux jetons.
        self._apercu, self._apercu_index, self._renommages = {}, {}, {}
        self._compteurs = Counter(t for t, _ in self.valide.values())
        # Jetons écrits tels quels dans le texte d'origine et inconnus de la conversation : réservés
        self._reserves = {jeton_canonique(m.group(1), m.group(2)) for m in JETON_RE.finditer(texte)} - set(self.valide)

        trouves = []
        termes_cf = {" ".join(t.split()).casefold() for t in termes}
        debuts, fins = [], []  # intervalles déjà pris, triés et sans chevauchement

        def prendre(d, f):
            i = bisect.bisect_right(debuts, d)
            if i and fins[i - 1] > d:          # chevauche l'intervalle précédent
                return False
            if i < len(debuts) and debuts[i] < f:  # chevauche le suivant
                return False
            debuts.insert(i, d)
            fins.insert(i, f)
            return True

        for type_, motif in MOTIFS:
            if types is not None and type_ not in types and not (type_ == "IP" and set(TYPES_IP) & set(types)):
                continue
            for m in motif.finditer(texte):
                if type_ == "DN":
                    for d, f, sous_type, valeur in _decomposer_dn(m, termes_cf):
                        if f > d and prendre(d, f):
                            trouves.append((d, f, sous_type, valeur))
                    continue
                d, f = _plage(m)
                if f > d and _accepte(type_, m, texte[d:f]):
                    sorte = type_ip(texte[d:f]) if type_ == "IP" else type_
                    if (types is None or sorte in types) and prendre(d, f):
                        trouves.append((d, f, sorte, texte[d:f]))

        for brut in motifs:
            try:
                motif = compiler_motif(brut)
            except re.error:
                continue
            for m in motif.finditer(texte):
                d, f = _plage(m)
                if f > d and prendre(d, f):
                    trouves.append((d, f, "PERSO", texte[d:f]))

        # Une valeur déjà masquée dans la conversation est masquée partout où elle réapparaît,
        # même sans le contexte qui l'a fait détecter (« user slefevre » après « C:\\Users\\slefevre »).
        connues = [(v, t) for t, v in self.valide.values()] + [(v, t) for _, _, t, v in trouves]
        # DOMAINE\utilisateur : le domaine et l'utilisateur seuls sont aussi masqués ailleurs
        # (« vallorie\jdoe » dans la sortie de whoami, « Account Name: jdoe »)
        for valeur, type_ in list(connues):
            if type_ == "COMPTE" and valeur.count("\\") == 1:
                domaine, utilisateur = valeur.split("\\")
                if domaine.upper() not in DOMAINES_SYSTEME and re.fullmatch(r"[A-Za-z][\w-]{1,14}", domaine):
                    connues.append((domaine, "FQDN\\"))  # seulement devant « \ » : pas « Acme SAS »
                if utilisateur.lower() not in COMPTES_NEUTRES:
                    connues.append((utilisateur, "COMPTE"))
        for d, f, type_, valeur in self._occurrences_connues(texte, connues, types):
            if prendre(d, f):
                trouves.append((d, f, type_, valeur))

        propres = {" ".join(t.split()) for t in termes}
        for terme in sorted((t for t in propres if len(t) >= 2), key=len, reverse=True):
            motif = re.compile(
                r"(?<!\w)" + r"\s+".join(map(_motif_mot, terme.split())) + r"(?!\w)", re.IGNORECASE)
            for m in motif.finditer(texte):
                if prendre(*m.span()):
                    trouves.append((m.start(), m.end(), "NOM", terme))

        trouves.sort()
        res = Resultat(texte="")
        morceaux, pos, taille = [], 0, 0
        for d, f, type_, valeur in trouves:
            jeton = self._jeton(type_, valeur)
            if jeton not in res.ordre:
                res.ordre.append(jeton)
            if jeton in self.exclus:
                res.ignores[jeton] += 1
                continue
            avant = texte[pos:d]
            morceaux.append(avant)
            taille += len(avant)
            morceaux.append(jeton)
            res.spans_sortie.append((taille, taille + len(jeton), jeton))
            taille += len(jeton)
            res.spans_source.append((d, f, jeton))
            res.compte[jeton] += 1
            pos = f
        morceaux.append(texte[pos:])
        res.texte = "".join(morceaux)
        return res

    @staticmethod
    def _occurrences_connues(texte, connues, types):
        """Occurrences littérales de valeurs déjà connues : (début, fin, type, texte trouvé).

        Recherche directe (str.find) valeur par valeur : une seule expression régulière avec des
        milliers d'alternatives serait trente fois plus lente sur un gros fichier de logs.
        """
        par_valeur = {}
        for valeur, type_ in connues:
            if len(valeur) >= 3 and "\n" not in valeur and (types is None or type_.rstrip("\\") in types or
                                                            type_ in ("NOM", "PERSO")):
                par_valeur.setdefault(valeur if type_ in EXACTS else valeur.lower(), (type_, valeur))
        minuscules = texte.lower()
        if len(minuscules) != len(texte):  # caractère dont la minuscule change la longueur : cas rare
            minuscules = None

        def mot(c):
            return c.isalnum() or c == "_"

        sortie = []
        for cle in sorted(par_valeur, key=len, reverse=True):  # les plus longues d'abord
            type_, valeur = par_valeur[cle]
            exact = type_ in EXACTS
            if exact or minuscules is not None:
                cible = texte if exact else minuscules
                positions = []
                pos = cible.find(cle)
                while pos != -1:
                    positions.append(pos)
                    pos = cible.find(cle, pos + 1)
            else:
                positions = [m.start() for m in re.finditer(re.escape(valeur), texte, re.IGNORECASE)]
            n = len(valeur)
            devant_barre = type_.endswith("\\")  # domaine NetBIOS déduit d'un DOMAINE\utilisateur
            for pos in positions:
                if devant_barre and (pos + n >= len(texte) or texte[pos + n] != "\\"):
                    continue
                if mot(valeur[0]) and pos > 0 and mot(texte[pos - 1]):
                    continue
                if mot(valeur[-1]) and pos + n < len(texte) and mot(texte[pos + n]):
                    continue
                sortie.append((pos, pos + n, type_.rstrip("\\"), texte[pos:pos + n]))
        return sortie

    def _jetons_trouves(self, texte):
        """(match, jeton canonique) pour les jetons automatiques et personnalisés, dans l'ordre du texte."""
        trouves = [(m, jeton_canonique(m.group(1), m.group(2))) for m in JETON_RE.finditer(texte)]
        perso = {j[1:-1] for j in (*self.valide, *self._apercu) if not JETON_RE.fullmatch(j)}
        if perso:
            noms = sorted(perso, key=len, reverse=True)
            motif = re.compile(r"\\?\[\s*(" + "|".join(re.escape(n).replace("_", r"\\?_") for n in noms)
                               + r")\s*\\?\]", re.IGNORECASE)
            canonique = {n.casefold(): n for n in noms}
            pris = [(m.start(), m.end()) for m, _ in trouves]
            for m in motif.finditer(texte):
                if not any(d < m.end() and m.start() < f for d, f in pris):
                    nom = canonique.get(m.group(1).replace("\\", "").casefold())
                    if nom:
                        trouves.append((m, f"[{nom}]"))
            trouves.sort(key=lambda x: x[0].start())
        return trouves

    def restaurer(self, texte):
        res = Resultat(texte="")
        morceaux, pos, taille = [], 0, 0
        for m, jeton in self._jetons_trouves(texte):
            info = self.info(jeton)
            if not info:
                res.inconnus.append((m.start(), m.end(), m.group(0)))
                continue
            valeur = info[1]
            brut = m.group(0)
            if brut.startswith("\\") and not brut.endswith("\\]"):
                valeur = "\\" + valeur  # C:\Users\[COMPTE_1] : l'antislash fait partie du chemin
            avant = texte[pos:m.start()]
            morceaux.append(avant)
            taille += len(avant)
            morceaux.append(valeur)
            res.spans_sortie.append((taille, taille + len(valeur), jeton))
            taille += len(valeur)
            res.spans_source.append((m.start(), m.end(), jeton))
            res.compte[jeton] += 1
            pos = m.end()
        morceaux.append(texte[pos:])
        res.texte = "".join(morceaux)
        return res
