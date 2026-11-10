"""Réglages et conversations enregistrés dans %APPDATA%\\IA-Anonymiser.

Les conversations contiennent les vraies valeurs : sous Windows, elles sont chiffrées avec
DPAPI (CryptProtectData), c'est-à-dire avec le compte Windows de l'utilisateur. Un autre compte,
ou une copie du fichier sur une autre machine, ne peut pas les lire.
"""
import json
import locale
import os
import sys

from moteur import TYPES_AUTO

ENTETE_DPAPI = b"IAA1"
ENTETE_CLAIR = b"IAA0"  # hors Windows uniquement (développement)


def dossier_config():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    dossier = os.path.join(base, "IA-Anonymiser")
    os.makedirs(dossier, exist_ok=True)
    return dossier


def langue_systeme():
    try:
        if sys.platform == "win32":
            import ctypes
            code = locale.windows_locale.get(ctypes.windll.kernel32.GetUserDefaultUILanguage(), "")
        else:
            code = locale.getlocale()[0] or os.environ.get("LANG", "")
    except Exception:
        code = ""
    return "fr" if code.lower().startswith("fr") else "en"


def theme_systeme():
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as cle:
                return "clair" if winreg.QueryValueEx(cle, "AppsUseLightTheme")[0] else "sombre"
        except OSError:
            pass
    return "clair"


# --- DPAPI -----------------------------------------------------------------
def _dpapi(donnees, chiffrer):
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    tampon = ctypes.create_string_buffer(donnees, len(donnees))
    entree = BLOB(len(donnees), ctypes.cast(tampon, ctypes.POINTER(ctypes.c_char)))
    sortie = BLOB()
    sans_fenetre = 0x01  # CRYPTPROTECT_UI_FORBIDDEN
    if chiffrer:
        ok = crypt32.CryptProtectData(ctypes.byref(entree), ctypes.c_wchar_p("IA-Anonymiser"),
                                      None, None, None, sans_fenetre, ctypes.byref(sortie))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(entree), None, None, None, None, sans_fenetre,
                                        ctypes.byref(sortie))
    if not ok:
        raise OSError(f"DPAPI : erreur {ctypes.GetLastError()}")
    try:
        return ctypes.string_at(sortie.pbData, sortie.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(sortie.pbData, ctypes.c_void_p))


def proteger(donnees):
    if sys.platform == "win32":
        return ENTETE_DPAPI + _dpapi(donnees, True)
    return ENTETE_CLAIR + donnees


def deproteger(contenu):
    if contenu.startswith(ENTETE_DPAPI):
        return _dpapi(contenu[len(ENTETE_DPAPI):], False)
    if contenu.startswith(ENTETE_CLAIR) and sys.platform != "win32":
        return contenu[len(ENTETE_CLAIR):]
    raise ValueError("format inconnu")


# --- fichiers ----------------------------------------------------------------
def trier(termes):
    vus, sortie = set(), []
    for t in termes:
        t = " ".join(str(t).split())
        if len(t) >= 2 and t.casefold() not in vus:
            vus.add(t.casefold())
            sortie.append(t)
    return sorted(sortie, key=str.casefold)


class Options:
    def __init__(self, dossier=None):
        self.dossier = dossier or dossier_config()
        self.chemin = os.path.join(self.dossier, "options.json")
        self.types = set(TYPES_AUTO)
        self.permanents = []
        self.consigne = True
        self.consigne_texte = None   # None : texte par défaut, dans la langue de l'interface
        self.langue = "auto"         # auto, fr, en
        self.theme = "auto"          # auto, clair, sombre
        self.conserver = True        # conversations gardées entre deux lancements
        self.charger()

    def langue_effective(self):
        return self.langue if self.langue in ("fr", "en") else langue_systeme()

    def theme_effectif(self):
        return self.theme if self.theme in ("clair", "sombre") else theme_systeme()

    def charger(self):
        try:
            with open(self.chemin, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            # Reprise de la liste de termes de la version 1.1
            try:
                with open(os.path.join(self.dossier, "termes.txt"), encoding="utf-8") as f:
                    self.permanents = trier(f)
            except OSError:
                pass
            return
        self.types = {t for t in d.get("types", TYPES_AUTO) if t in TYPES_AUTO}
        self.permanents = trier(d.get("permanents", []))
        self.consigne = bool(d.get("consigne", True))
        texte = d.get("consigne_texte")
        self.consigne_texte = texte if isinstance(texte, str) and texte.strip() else None
        self.langue = d.get("langue") if d.get("langue") in ("auto", "fr", "en") else "auto"
        self.theme = d.get("theme") if d.get("theme") in ("auto", "clair", "sombre") else "auto"
        self.conserver = bool(d.get("conserver", True))

    def sauver(self):
        with open(self.chemin, "w", encoding="utf-8") as f:
            json.dump({"types": sorted(self.types), "permanents": self.permanents,
                       "consigne": self.consigne, "consigne_texte": self.consigne_texte,
                       "langue": self.langue, "theme": self.theme, "conserver": self.conserver},
                      f, ensure_ascii=False, indent=2)


def chemin_conversations(dossier=None):
    return os.path.join(dossier or dossier_config(), "conversations.dat")


def sauver_conversations(donnees, dossier=None):
    chemin = chemin_conversations(dossier)
    temporaire = chemin + ".tmp"
    with open(temporaire, "wb") as f:
        f.write(proteger(json.dumps(donnees, ensure_ascii=False).encode("utf-8")))
    os.replace(temporaire, chemin)


def charger_conversations(dossier=None):
    """Renvoie les données enregistrées, None si aucun fichier. Lève une exception si illisible."""
    chemin = chemin_conversations(dossier)
    if not os.path.exists(chemin):
        return None
    with open(chemin, "rb") as f:
        return json.loads(deproteger(f.read()).decode("utf-8"))


def effacer_conversations(dossier=None):
    try:
        os.remove(chemin_conversations(dossier))
    except OSError:
        pass
