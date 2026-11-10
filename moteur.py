"""Moteur d'IA-Anonymiser : détection des données personnelles, jetons et restauration.

Les correspondances jeton -> valeur restent en mémoire uniquement.
"""
import bisect
import re
from collections import Counter
from dataclasses import dataclass, field

# Préfixe des jetons selon la langue de l'interface : [NOM_1] en français, [NAME_1] en anglais.
PREFIXES = {
    "fr": {"EMAIL": "EMAIL", "TEL": "TEL", "IBAN": "IBAN", "CARTE": "CARTE", "SECU": "SECU",
           "IP": "IP", "MAC": "MAC", "FQDN": "FQDN", "SECRET": "SECRET", "COMPTE": "COMPTE",
           "DN": "DN", "SID": "SID", "PERSO": "REF", "NOM": "NOM"},
    "en": {"EMAIL": "EMAIL", "TEL": "PHONE", "IBAN": "IBAN", "CARTE": "CARD", "SECU": "SSN",
           "IP": "IP", "MAC": "MAC", "FQDN": "FQDN", "SECRET": "SECRET", "COMPTE": "ACCOUNT",
           "DN": "DN", "SID": "SID", "PERSO": "REF", "NOM": "NAME"},
}
TOUS_PREFIXES = sorted({p for d in PREFIXES.values() for p in d.values()}, key=len, reverse=True)

# Types détectés automatiquement (les termes et les motifs personnalisés sont à part).
TYPES_AUTO = ["EMAIL", "TEL", "IBAN", "CARTE", "SECU", "IP", "MAC", "FQDN", "SECRET", "COMPTE", "DN", "SID"]
# Types de la version 1.3 : les types ajoutés depuis sont activés pour les utilisateurs existants.
TYPES_V13 = ["EMAIL", "TEL", "IBAN", "CARTE", "SECU", "IP", "MAC", "FQDN"]

EXEMPLES = {
    "EMAIL": "jean.dupont@exemple.fr",
    "TEL": "06 12 34 56 78, +33 1 23 45 67 89",
    "IBAN": "FR76 3000 6000 0112 3456 7890 189",
    "CARTE": "4111 1111 1111 1111",
    "SECU": "1 85 05 78 006 084 36",
    "IP": "192.168.1.10",
    "MAC": "00:1A:2B:3C:4D:5E",
    "FQDN": "srv-paie01.acme.local, intranet.acme.fr",
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

# Ordre important : les motifs les plus spécifiques passent en premier.
MOTIFS = [
    ("SECRET", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("SECRET", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<v>[^\s@/]+)@", re.IGNORECASE)),
    ("SECRET", re.compile(r"\b(?:bearer|basic)\s+(?P<v>[A-Za-z0-9\-._~+/]{12,}=*)", re.IGNORECASE)),
    ("SECRET", re.compile(r"<(?P<k>password|pwd|secret|token|apikey|api_key)>(?P<v>[^<]+)</(?P=k)>",
                          re.IGNORECASE)),
    ("SECRET", re.compile(r"(?<![\w.-])(?:[\w.-]*[_.-])?(?:" + _CLES_SECRETES + r")[\"']?\s*[:=]\s*" + _VALEUR,
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
    ("DN", re.compile(
        r"(?<![\w=])(?:CN|OU|DC|O|L|ST|C|UID)=[^,=\n+\"<>;()]+(?:\s*,\s*(?:CN|OU|DC|O|L|ST|C|UID)=[^,=\n+\"<>;()]+)+",
        re.IGNORECASE)),
    ("SID", re.compile(r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b")),
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b")),
    ("SECU", re.compile(
        r"(?<![\d\w])[12][\s.]?\d{2}[\s.]?(?:0[1-9]|1[0-2]|[2-9]\d)[\s.]?(?:\d{2}|2[AB])"
        r"[\s.]?\d{3}[\s.]?\d{3}(?:[\s.]?\d{2})?(?![\d\w])")),
    ("CARTE", re.compile(r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)")),
    ("TEL", re.compile(
        r"(?<![\w+])(?:(?:\+|00)33\s?(?:\(0\)\s?)?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\w)"  # France
        r"|(?<![\w+])\+\d{1,3}[\s.-]?\d{1,4}(?:[\s.-]?\d{2,4}){2,4}(?!\w)"           # international
    )),
    # Comptes : DOMAINE\utilisateur (domaine NetBIOS en majuscules), et l'utilisateur dans un chemin de profil
    ("COMPTE", re.compile(r"(?<![\w\\/.-])(?P<d>[A-Z][A-Z0-9-]{1,14})\\[A-Za-z0-9][\w.$-]{1,63}(?![\w\\])")),
    ("COMPTE", re.compile(
        r"\b[a-z]:\\(?:users|documents and settings)\\(?P<v>[^\\/\n:*?\"<>|]+(?=\\)|[^\\/\s:*?\"<>|]+)",
        re.IGNORECASE)),
    ("COMPTE", re.compile(r"(?<![\w./-])/(?:home|Users)/(?P<v>[A-Za-z0-9._-]+)")),
    ("IP", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")),
    ("MAC", re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")),
    ("FQDN", re.compile(
        r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?P<tld>[a-z]{2,63})(?![\w-]|\.\w)",
        re.IGNORECASE)),
]

DOMAINES_SYSTEME = {"BUILTIN", "NT", "AUTHORITY", "SERVICE", "APPPOOL", "WORKGROUP", "HKLM", "HKCU", "HKCR",
                    "HKU", "HKCC", "SYSTEM", "LOCAL"}
PROFILS_GENERIQUES = {"public", "default", "default user", "all users", "shared", "guest"}


def _accepte(type_, m, valeur):
    if type_ == "FQDN":
        tld = m.group("tld").lower()
        return tld not in EXTENSIONS_FICHIERS and (len(tld) == 2 or tld in EXTENSIONS_DOMAINE)
    if type_ == "COMPTE":
        domaine = m.groupdict().get("d")
        if domaine and (domaine in DOMAINES_SYSTEME or domaine.startswith("HKEY")):
            return False
        return valeur.strip().lower() not in PROFILS_GENERIQUES
    return True


def _plage(m):
    """Partie à masquer : le groupe « v » s'il existe, sinon tout ; sans espaces en bout."""
    debut, fin = m.span("v") if "v" in m.re.groupindex and m.group("v") else m.span()
    texte = m.string
    while fin > debut and texte[fin - 1].isspace():
        fin -= 1
    return debut, fin


def compiler_motif(motif):
    """Motif personnalisé (expression régulière), insensible à la casse. Lève re.error s'il est invalide."""
    rx = re.compile(motif, re.IGNORECASE)
    if rx.match(""):
        raise re.error("le motif ne doit pas accepter un texte vide")
    return rx


# Tolère les variantes qu'une IA peut produire : [nom_1], [ NOM_1 ], [NOM 1], \[NOM\_1\] (Markdown)…
JETON_RE = re.compile(
    r"\\?\[\s*(" + "|".join(TOUS_PREFIXES) + r")\s*(?:\\?_|-|\s)?\s*(\d+)\s*\\?\]",
    re.IGNORECASE,
)


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

    # --- jetons -----------------------------------------------------------
    def _jeton(self, type_, valeur):
        cle = (type_, _cle(valeur, type_))
        jeton = self.index.get(cle) or self._apercu_index.get(cle)
        if jeton:
            return jeton
        self._compteurs[type_] += 1
        n = self._compteurs[type_]
        jeton = f"[{PREFIXES.get(self.langue, PREFIXES['fr'])[type_]}_{n}]"
        self._apercu[jeton] = (type_, valeur)
        self._apercu_index[cle] = jeton
        return jeton

    def info(self, jeton):
        return self.valide.get(jeton) or self._apercu.get(jeton)

    def jetons(self):
        """Tous les jetons de la conversation, dans l'ordre de création."""
        return list(self.valide) + [j for j in self._apercu if j not in self.valide]

    def etat(self):
        return {"valide": {j: list(v) for j, v in self.valide.items()}, "exclus": sorted(self.exclus)}

    def charger_etat(self, etat):
        self.reinitialiser()
        for jeton, (type_, valeur) in etat.get("valide", {}).items():
            self.valide[jeton] = (type_, valeur)
            self.index[(type_, _cle(valeur, type_))] = jeton
        self.exclus = set(etat.get("exclus", [])) & set(self.valide)
        self._compteurs = Counter(t for t, _ in self.valide.values())

    def valider(self):
        """Fige les jetons du texte en cours (à appeler quand il est copié pour l'IA)."""
        self.valide.update(self._apercu)
        self.index.update(self._apercu_index)
        self._apercu, self._apercu_index = {}, {}
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
        self._apercu, self._apercu_index = {}, {}
        self._compteurs = Counter(t for t, _ in self.valide.values())

        trouves = []
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
            if types is not None and type_ not in types:
                continue
            for m in motif.finditer(texte):
                d, f = _plage(m)
                if f > d and _accepte(type_, m, texte[d:f]) and prendre(d, f):
                    trouves.append((d, f, type_, texte[d:f]))

        for brut in motifs:
            try:
                motif = compiler_motif(brut)
            except re.error:
                continue
            for m in motif.finditer(texte):
                d, f = _plage(m)
                if f > d and prendre(d, f):
                    trouves.append((d, f, "PERSO", texte[d:f]))

        propres = {" ".join(t.split()) for t in termes}
        for terme in sorted((t for t in propres if len(t) >= 2), key=len, reverse=True):
            motif = re.compile(
                r"(?<!\w)" + r"\s+".join(map(re.escape, terme.split())) + r"(?!\w)", re.IGNORECASE)
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

    def restaurer(self, texte):
        res = Resultat(texte="")
        morceaux, pos, taille = [], 0, 0
        for m in JETON_RE.finditer(texte):
            jeton = f"[{m.group(1).upper()}_{int(m.group(2))}]"
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
