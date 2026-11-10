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
           "IP": "IP", "MAC": "MAC", "FQDN": "FQDN", "NOM": "NOM"},
    "en": {"EMAIL": "EMAIL", "TEL": "PHONE", "IBAN": "IBAN", "CARTE": "CARD", "SECU": "SSN",
           "IP": "IP", "MAC": "MAC", "FQDN": "FQDN", "NOM": "NAME"},
}
TOUS_PREFIXES = sorted({p for d in PREFIXES.values() for p in d.values()}, key=len, reverse=True)

# Types détectés automatiquement (les termes personnalisés sont à part).
TYPES_AUTO = ["EMAIL", "TEL", "IBAN", "CARTE", "SECU", "IP", "MAC", "FQDN"]

EXEMPLES = {
    "EMAIL": "jean.dupont@exemple.fr",
    "TEL": "06 12 34 56 78, +33 1 23 45 67 89",
    "IBAN": "FR76 3000 6000 0112 3456 7890 189",
    "CARTE": "4111 1111 1111 1111",
    "SECU": "1 85 05 78 006 084 36",
    "IP": "192.168.1.10",
    "MAC": "00:1A:2B:3C:4D:5E",
    "FQDN": "srv-paie01.acme.local, intranet.acme.fr",
}

# Un « domaine » qui se termine par une extension de fichier est un nom de fichier (rapport.pdf).
EXTENSIONS_FICHIERS = set(
    "pdf doc docx docm xls xlsx xlsm csv ppt pptx odt ods odp rtf txt md log ini cfg conf json xml yml "
    "yaml toml html htm css js ts jsx tsx py java cs cpp go rs rb php sql sh bat cmd ps1 vbs exe dll msi "
    "jar apk zip rar 7z gz tar iso png jpg jpeg gif bmp svg webp ico mp3 mp4 wav mov avi mkv eml msg "
    "tmp bak old dat db sqlite lnk".split())

# Ordre important : les motifs les plus spécifiques passent en premier.
MOTIFS = [
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
    ("IP", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")),
    ("MAC", re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")),
    ("FQDN", re.compile(
        r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63})(?![\w-]|\.\w)",
        re.IGNORECASE)),
]


def _accepte(type_, m):
    if type_ == "FQDN":
        return m.group(1).lower() not in EXTENSIONS_FICHIERS
    return True

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
    def anonymiser(self, texte, termes=(), types=None):
        """types : ensemble des types détectés automatiquement (None = tous)."""
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
                if _accepte(type_, m) and prendre(*m.span()):
                    trouves.append((m.start(), m.end(), type_, m.group(0)))

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
