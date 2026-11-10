"""Moteur d'IA-Anonymiser : détection des données personnelles, jetons et restauration.

Les correspondances jeton -> valeur restent en mémoire uniquement.
"""
import re
from collections import Counter
from dataclasses import dataclass, field

LIBELLES = {
    "EMAIL": "E-mail",
    "TEL": "Téléphone",
    "IBAN": "IBAN",
    "CARTE": "Carte bancaire",
    "SECU": "N° de sécurité sociale",
    "IP": "Adresse IP",
    "MAC": "Adresse MAC",
    "FQDN": "Nom de domaine (FQDN)",
    "NOM": "Terme personnalisé",
}

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
    r"\\?\[\s*(" + "|".join(LIBELLES) + r")\s*(?:\\?_|-|\s)?\s*(\d+)\s*\\?\]",
    re.IGNORECASE,
)


def _cle(valeur):
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
    def __init__(self):
        self.reinitialiser()

    def reinitialiser(self):
        self.valide = {}      # jeton -> (type, valeur) : déjà envoyé à l'IA
        self.index = {}       # (type, clé) -> jeton
        self.exclus = set()   # jetons que l'utilisateur ne veut plus masquer
        self._apercu = {}     # jetons du texte en cours, pas encore copiés
        self._apercu_index = {}

    # --- jetons -----------------------------------------------------------
    def _jeton(self, type_, valeur):
        cle = (type_, _cle(valeur))
        jeton = self.index.get(cle) or self._apercu_index.get(cle)
        if jeton:
            return jeton
        n = 1 + sum(1 for t, _ in (*self.valide.values(), *self._apercu.values()) if t == type_)
        jeton = f"[{type_}_{n}]"
        self._apercu[jeton] = (type_, valeur)
        self._apercu_index[cle] = jeton
        return jeton

    def info(self, jeton):
        return self.valide.get(jeton) or self._apercu.get(jeton)

    def valider(self):
        """Fige les jetons du texte en cours (à appeler quand il est copié pour l'IA)."""
        self.valide.update(self._apercu)
        self.index.update(self._apercu_index)
        self._apercu, self._apercu_index = {}, {}

    def reinclure(self, type_, valeur):
        cle = (type_, _cle(valeur))
        jeton = self.index.get(cle) or self._apercu_index.get(cle)
        self.exclus.discard(jeton)

    # --- traitements ------------------------------------------------------
    def anonymiser(self, texte, termes=(), types=None):
        """types : ensemble des types détectés automatiquement (None = tous)."""
        # Les jetons d'un aperçu non copié sont recalculés à chaque fois : taper
        # « jean@ex.f » puis « jean@ex.fr » ne crée pas deux jetons.
        self._apercu, self._apercu_index = {}, {}

        trouves, occupe = [], []

        def libre(d, f):
            return all(f <= a or d >= b for a, b in occupe)

        for type_, motif in MOTIFS:
            if types is not None and type_ not in types:
                continue
            for m in motif.finditer(texte):
                if libre(*m.span()) and _accepte(type_, m):
                    trouves.append((m.start(), m.end(), type_, m.group(0)))
                    occupe.append(m.span())

        propres = {" ".join(t.split()) for t in termes}
        for terme in sorted((t for t in propres if len(t) >= 2), key=len, reverse=True):
            motif = re.compile(
                r"(?<!\w)" + r"\s+".join(map(re.escape, terme.split())) + r"(?!\w)", re.IGNORECASE)
            for m in motif.finditer(texte):
                if libre(*m.span()):
                    trouves.append((m.start(), m.end(), "NOM", terme))
                    occupe.append(m.span())

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
