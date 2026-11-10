"""IA-Anonymiser : interface graphique.

À gauche : les conversations. Onglet 1 : texte original / version anonymisée.
Onglet 2 : réponse de l'IA / vraies valeurs. En bas : éléments masqués et termes de la conversation.
"""
import bisect
import json
import os
import platform
import sys
import threading
import tkinter as tk
import urllib.request
import webbrowser
from tkinter import font as tkfont
from tkinter import messagebox, simpledialog, ttk

import stockage
from moteur import EXEMPLES, TYPES_AUTO, Anonymiseur, compiler_motif
from textes import CONSIGNES, Traducteur

try:
    import sv_ttk  # thème Sun Valley (style Windows 11), clair et sombre
except ImportError:
    sv_ttk = None

try:
    from version import VERSION
except ImportError:
    VERSION = "dev"

DEPOT = "https://github.com/Some0neElseIsHere/IA-Anonymiser"
API_DERNIERE = "https://api.github.com/repos/Some0neElseIsHere/IA-Anonymiser/releases/latest"
DELAI_MS = 250
SAUVEGARDE_MS = 15000
THEME_MS = 4000

PALETTES = {
    "clair": {
        "fond": "#ffffff", "fond_lecture": "#f7f7f8", "texte": "#1b1b1b", "bordure": "#d4d4d8",
        "focus": "#005fb8", "selection": "#b9d6f2", "aide": "#5f6368", "lien": "#005fb8",
        "masque": ("#fff0a6", "#1b1b1b"), "actif": ("#ffc94d", "#1b1b1b"),
        "jeton": ("#d2f0dc", "#0f5132"), "inconnu": ("#ffd6d6", "#8b0000"), "absent": "#8a8a8a",
    },
    "sombre": {
        "fond": "#262626", "fond_lecture": "#1f1f1f", "texte": "#e8e8e8", "bordure": "#3d3d3d",
        "focus": "#57c8ff", "selection": "#1f4e79", "aide": "#a3a3a3", "lien": "#57c8ff",
        "masque": ("#5a4a00", "#fff2b3"), "actif": ("#8f6c00", "#ffffff"),
        "jeton": ("#1d4a32", "#c9f2d6"), "inconnu": ("#5c2020", "#ffd6d6"), "absent": "#7a7a7a",
    },
}


def ressource(nom):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "assets", nom)


def activer_dpi():
    """Évite le texte flou sur les écrans Windows mis à l'échelle (125 %, 150 %…)."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def barre_de_titre(fenetre, sombre):
    """Barre de titre Windows sombre ou claire, assortie au thème."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        fenetre.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(fenetre.winfo_id())
        valeur = ctypes.c_int(1 if sombre else 0)
        for attribut in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (Windows 11 / anciennes versions de 10)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribut, ctypes.byref(valeur),
                                                          ctypes.sizeof(valeur)) == 0:
                break
    except Exception:
        pass


def normaliser(terme):
    return " ".join(terme.split())


def version_tuple(v):
    try:
        return tuple(int(x) for x in v.lstrip("vV").split("."))
    except ValueError:
        return None


class Conversation:
    def __init__(self, nom, langue):
        self.nom = nom
        self.moteur = Anonymiseur(langue)
        self.termes = []
        self.source = ""
        self.reponse = ""

    def etat(self):
        return {"nom": self.nom, "termes": self.termes, "source": self.source, "reponse": self.reponse,
                "moteur": self.moteur.etat()}

    @classmethod
    def depuis_etat(cls, d, langue):
        c = cls(str(d.get("nom") or "?"), langue)
        c.termes = stockage.trier(d.get("termes", []))
        c.source = str(d.get("source", ""))
        c.reponse = str(d.get("reponse", ""))
        c.moteur.charger_etat(d.get("moteur", {}))
        return c


class Zone(ttk.Frame):
    """Zone de texte avec un titre, des boutons et une barre de défilement."""

    def __init__(self, app, parent, titre, lecture_seule=False, marge=(0, 0, 0, 0)):
        super().__init__(parent, padding=marge)
        self.entete = ttk.Frame(self)
        self.entete.pack(fill="x", pady=(0, 8))
        ttk.Label(self.entete, text=titre, style="Titre.TLabel").pack(side="left")
        cadre = ttk.Frame(self)
        cadre.pack(fill="both", expand=True)
        self.texte = tk.Text(cadre, wrap="word", font=app.police, undo=not lecture_seule, relief="flat",
                             borderwidth=0, padx=14, pady=10, highlightthickness=1, spacing1=3, spacing3=3)
        barre = ttk.Scrollbar(cadre, command=self.texte.yview)
        self.texte.configure(yscrollcommand=barre.set)
        barre.pack(side="right", fill="y", padx=(4, 0))
        self.texte.pack(side="left", fill="both", expand=True)
        self.lecture_seule = lecture_seule
        if lecture_seule:
            self.texte.configure(state="disabled")
        app.textes_tk.append(self)

    def bouton(self, texte, commande, accent=False):
        """Ajoute un bouton à droite du titre (le premier ajouté est le plus à droite)."""
        b = ttk.Button(self.entete, text=texte, command=commande, style="Accent.TButton" if accent else "TButton")
        b.pack(side="right", padx=(8, 0))
        return b

    def colorer(self, p):
        self.texte.configure(background=p["fond_lecture"] if self.lecture_seule else p["fond"],
                             foreground=p["texte"], insertbackground=p["texte"],
                             selectbackground=p["selection"], selectforeground=p["texte"],
                             inactiveselectbackground=p["selection"],
                             highlightbackground=p["bordure"], highlightcolor=p["focus"])
        for nom in ("masque", "actif", "jeton", "inconnu"):
            fond, texte = p[nom]
            self.texte.tag_configure(nom, background=fond, foreground=texte)
        self.texte.tag_raise("actif")
        self.texte.tag_raise("sel")

    def lire(self):
        return self.texte.get("1.0", "end-1c")

    def ecrire(self, contenu, spans=(), tag=None):
        position = self.texte.yview()[0]
        self.texte.configure(state="normal")
        self.texte.delete("1.0", "end")
        self.texte.insert("1.0", contenu)
        if tag:
            self.surligner(spans, tag, contenu)
        self.texte.yview_moveto(position)
        if self.lecture_seule:
            self.texte.configure(state="disabled")
        else:
            self.texte.edit_reset()

    def surligner(self, spans, tag, contenu=None):
        """Colore des plages (début, fin) exprimées en caractères depuis le début du texte.

        Les positions sont converties en « ligne.colonne » : avec « 1.0+Nc », Tk recompte le texte
        depuis le début à chaque plage, ce qui fige l'application sur un gros fichier de logs.
        """
        self.texte.tag_remove(tag, "1.0", "end")
        if not spans:
            return
        contenu = self.lire() if contenu is None else contenu
        lignes = [0]
        position = contenu.find("\n")
        while position != -1:
            lignes.append(position + 1)
            position = contenu.find("\n", position + 1)

        def index(n):
            ligne = bisect.bisect_right(lignes, n) - 1
            return f"{ligne + 1}.{n - lignes[ligne]}"

        plages = []
        for debut, fin, _ in spans:
            plages += (index(debut), index(fin))
            if len(plages) >= 1000:
                self.texte.tag_add(tag, *plages)
                plages = []
        if plages:
            self.texte.tag_add(tag, *plages)


class ListeTermes(ttk.Frame):
    """Champ de saisie, bouton Ajouter et liste de termes."""

    def __init__(self, app, parent, ajouter, supprimer, hauteur=6):
        super().__init__(parent)
        ligne = ttk.Frame(self)
        ligne.pack(fill="x", pady=(0, 8))
        self.champ = ttk.Entry(ligne, font=app.police)
        self.champ.pack(side="left", fill="x", expand=True)
        self.champ.bind("<Return>", lambda e: ajouter())
        ttk.Button(ligne, text=app.t("ajouter"), command=ajouter).pack(side="left", padx=(8, 0))
        zone = ttk.Frame(self)
        zone.pack(fill="both", expand=True)
        self.arbre = ttk.Treeview(zone, show="tree", selectmode="extended", height=hauteur)
        self.arbre.column("#0", width=200)
        barre = ttk.Scrollbar(zone, command=self.arbre.yview)
        self.arbre.configure(yscrollcommand=barre.set)
        barre.pack(side="right", fill="y", padx=(4, 0))
        self.arbre.pack(side="left", fill="both", expand=True)
        self.arbre.bind("<Delete>", lambda e: supprimer())
        self.termes = []

    def remplir(self, termes):
        self.termes = list(termes)
        self.arbre.delete(*self.arbre.get_children())
        for i, t in enumerate(self.termes):
            self.arbre.insert("", "end", iid=f"t{i}", text=t)

    def selection(self):
        return [self.termes[int(i[1:])] for i in self.arbre.selection()]

    def saisie(self):
        texte = normaliser(self.champ.get())
        self.champ.delete(0, "end")
        return texte


class Application:
    def __init__(self, root):
        self.root = root
        self.options = stockage.Options()
        self.t = Traducteur(self.options.langue_effective())
        self.conversations = []
        self.courante = 0
        self.numero = 0
        self.resultat = None
        self.attentes = {}
        self.theme_applique = None
        self.erreurs_vues = set()
        self.resultat_reponse = None
        self.textes_tk = []

        self.icones()
        self.dimensionner()
        self.polices()
        self.reprendre_conversations()
        self.construire()
        self.appliquer_theme()
        if not self.conversations:
            self.nouvelle_conversation()
        else:
            self.charger_zones()
        root.protocol("WM_DELETE_WINDOW", self.quitter)
        root.after(SAUVEGARDE_MS, self.sauvegarde_periodique)
        root.after(THEME_MS, self.suivre_theme_windows)

    @property
    def conv(self):
        return self.conversations[self.courante]

    @property
    def moteur(self):
        return self.conv.moteur

    @property
    def palette(self):
        return PALETTES[self.theme_applique or "clair"]

    def termes_actifs(self):
        return self.options.permanents + self.conv.termes

    def consigne(self):
        texte = self.options.consigne_texte or CONSIGNES[self.t.langue]
        return texte.rstrip() + "\n\n"

    # --- apparence --------------------------------------------------------
    def icones(self):
        self.icone_entete = self.icone_petite = None
        try:
            if sys.platform == "win32":
                self.root.iconbitmap(default=ressource("icone.ico"))
            self.icone_fenetre = tk.PhotoImage(file=ressource("icone.png"))
            self.root.iconphoto(True, self.icone_fenetre)
            self.icone_entete = tk.PhotoImage(file=ressource("icone-64.png"))
            self.icone_petite = self.icone_entete.subsample(2, 2)
        except (tk.TclError, OSError):
            pass

    def dimensionner(self):
        """Grande fenêtre centrée, adaptée à l'écran et à sa mise à l'échelle."""
        self.echelle = echelle = max(1.0, self.root.winfo_fpixels("1i") / 96)
        ecran_l, ecran_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        largeur = min(int(1480 * echelle), int(ecran_l * 0.92))
        hauteur = min(int(900 * echelle), int(ecran_h * 0.88))
        x, y = (ecran_l - largeur) // 2, max(0, (ecran_h - hauteur) // 2 - int(20 * echelle))
        self.root.geometry(f"{largeur}x{hauteur}+{x}+{y}")
        self.root.minsize(min(largeur, int(1000 * echelle)), min(hauteur, int(620 * echelle)))
        if largeur < 1200 * echelle:
            try:
                self.root.state("zoomed")  # petit écran : plein écran (Windows)
            except tk.TclError:
                pass

    def polices(self):
        familles = set(tkfont.families(self.root))
        self.famille = next((f for f in ("Segoe UI Variable Text", "Segoe UI") if f in familles),
                            tkfont.nametofont("TkDefaultFont").actual("family"))
        self.police = tkfont.Font(family=self.famille, size=11)

    def styles(self):
        p, f = self.palette, self.famille
        style = ttk.Style()
        for nom in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            tkfont.nametofont(nom).configure(family=f, size=10)
        style.configure("Titre.TLabel", font=(f, 11, "bold"))
        style.configure("Entete.TLabel", font=(f, 17, "bold"))
        style.configure("Marque.TLabel", font=(f, 14, "bold"))
        style.configure("Section.TLabel", font=(f, 12, "bold"))
        style.configure("Aide.TLabel", foreground=p["aide"])
        style.configure("Statut.TLabel", foreground=p["aide"])
        style.configure("Lien.TLabel", foreground=p["lien"], font=(f, 10, "underline"))
        style.configure("TNotebook.Tab", padding=(16, 6))
        hauteur = self.police.metrics("linespace") + int(12 * self.echelle)
        style.configure("Treeview", rowheight=hauteur, font=self.police)
        style.configure("Treeview.Heading", font=(f, 10, "bold"))
        self.arbre_elements_couleurs()

    def arbre_elements_couleurs(self):
        if hasattr(self, "arbre"):
            self.arbre.tag_configure("exclu", foreground=self.palette["absent"])
            self.arbre.tag_configure("absent", foreground=self.palette["absent"])

    def appliquer_theme(self, force=False):
        theme = self.options.theme_effectif()
        if theme == self.theme_applique and not force:
            return
        self.theme_applique = theme
        sombre = theme == "sombre"
        if sv_ttk:
            sv_ttk.set_theme("dark" if sombre else "light")
        else:
            style = ttk.Style()
            for nom in ("vista", "clam"):
                if nom in style.theme_names():
                    style.theme_use(nom)
                    break
        self.styles()
        p = self.palette
        for zone in self.textes_tk:
            if zone.winfo_exists():
                zone.colorer(p)
        for menu in (getattr(self, "menu", None), getattr(self, "menu_conv", None)):
            if menu:
                menu.configure(background=p["fond"], foreground=p["texte"], activebackground=p["selection"],
                               activeforeground=p["texte"], relief="flat", borderwidth=1)
        for fenetre in [self.root] + [w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel)]:
            barre_de_titre(fenetre, sombre)

    def suivre_theme_windows(self):
        if self.options.theme == "auto":
            self.appliquer_theme()
        self.root.after(THEME_MS, self.suivre_theme_windows)

    # --- construction -----------------------------------------------------
    def construire(self):
        t, root = self.t, self.root
        self.textes_tk = []
        root.title(f"IA-Anonymiser {VERSION}")


        self.lateral = lateral = ttk.Panedwindow(root, orient="horizontal")
        lateral.pack(fill="both", expand=True, padx=18, pady=12)
        lateral.add(self.construire_conversations(lateral), weight=0)

        self.onglets = ttk.Notebook(lateral)
        lateral.add(self.onglets, weight=1)

        o1 = ttk.Frame(self.onglets, padding=12)
        self.onglets.add(o1, text=t("onglet_anonymiser"))
        self.p1 = p1 = ttk.Panedwindow(o1, orient="horizontal")
        p1.pack(fill="both", expand=True)
        self.source = Zone(self, p1, t("texte_original"), marge=(0, 0, 10, 0))
        self.source.bouton(t("effacer"), lambda: self.vider(self.source))
        self.source.bouton(t("coller"), lambda: self.coller(self.source))
        self.sortie = Zone(self, p1, t("texte_ia"), lecture_seule=True, marge=(10, 0, 0, 0))
        self.bouton_copier_ia = self.sortie.bouton(t("copier_ia"), self.copier_sortie, accent=True)
        p1.add(self.source, weight=1)
        p1.add(self.sortie, weight=1)

        o2 = ttk.Frame(self.onglets, padding=12)
        self.onglets.add(o2, text=t("onglet_restaurer"))
        self.p2 = p2 = ttk.Panedwindow(o2, orient="horizontal")
        p2.pack(fill="both", expand=True)
        self.reponse = Zone(self, p2, t("reponse_ia"), marge=(0, 0, 10, 0))
        self.reponse.bouton(t("effacer"), lambda: self.vider(self.reponse))
        self.reponse.bouton(t("coller"), lambda: self.coller(self.reponse))
        self.restauree = Zone(self, p2, t("reponse_restauree"), lecture_seule=True, marge=(10, 0, 0, 0))
        self.bouton_copier = self.restauree.bouton(t("copier"), self.copier_restauree, accent=True)
        p2.add(self.reponse, weight=1)
        p2.add(self.restauree, weight=1)

        o3 = ttk.Frame(self.onglets, padding=12)
        self.onglets.add(o3, text=t("onglet_elements", n=0))
        self.p3 = p3 = ttk.Panedwindow(o3, orient="horizontal")
        p3.pack(fill="both", expand=True)
        p3.add(self.construire_elements(p3), weight=3)
        p3.add(self.construire_termes(p3), weight=2)

        self.source.texte.bind("<<Modified>>", lambda e: self.modifie(self.source.texte, self.actualiser))
        self.reponse.texte.bind("<<Modified>>",
                                lambda e: self.modifie(self.reponse.texte, self.actualiser_reponse))
        self.sortie.texte.bind("<<Copy>>", lambda e: self.valider(), add="+")
        self.menu = tk.Menu(root, tearoff=0)
        self.menu_conv = tk.Menu(root, tearoff=0)
        for zone, spans in ((self.source, lambda: self.resultat and self.resultat.spans_source),
                            (self.sortie, lambda: self.resultat and self.resultat.spans_sortie),
                            (self.reponse, lambda: self.resultat_reponse and self.resultat_reponse.spans_source),
                            (self.restauree, lambda: self.resultat_reponse and self.resultat_reponse.spans_sortie)):
            zone.texte.bind("<Button-3>", lambda e, z=zone, s=spans: self.menu_contextuel(e, z, s() or []))
        self.source.texte.bind("<Control-m>", lambda e: (self.masquer_selection(), "break")[1])
        self.proportion(self.lateral, lambda l, h: min(int(250 * self.echelle), l // 3))
        self.proportion(self.p3, lambda l, h: int(l * 0.62))
        self.proportion(self.p1, lambda l, h: l // 2)
        self.proportion(self.p2, lambda l, h: l // 2)

    def proportion(self, pan, position):
        """Place le séparateur d'un panneau dès qu'il a sa vraie taille, une seule fois.

        Placé plus tôt, quand la fenêtre n'est pas encore affichée (taille de 1 pixel), le
        séparateur se retrouve à 0 et écrase une colonne. Le second onglet n'a sa taille
        qu'au moment où il est affiché pour la première fois.
        """
        def au_redimensionnement(evenement):
            if getattr(pan, "_place", False) or evenement.width < 100 or evenement.height < 100:
                return
            pan._place = True
            try:
                pan.sashpos(0, position(evenement.width, evenement.height))
            except tk.TclError:
                pass

        pan.bind("<Configure>", au_redimensionnement, add="+")

    def construire_conversations(self, parent):
        t = self.t
        cadre = ttk.Frame(parent, padding=(0, 0, 14, 0))
        marque = ttk.Frame(cadre)
        marque.pack(fill="x", pady=(0, 14))
        if self.icone_petite:
            ttk.Label(marque, image=self.icone_petite).pack(side="left", padx=(0, 8))
        ttk.Label(marque, text="IA-Anonymiser", style="Marque.TLabel").pack(side="left")

        bas = ttk.Frame(cadre)
        bas.pack(side="bottom", fill="x", pady=(10, 0))
        ttk.Button(bas, text=t("a_propos"), command=self.ouvrir_a_propos).pack(side="bottom", fill="x")
        ttk.Button(bas, text=t("options"), command=self.ouvrir_options).pack(side="bottom", fill="x", pady=(0, 8))
        ttk.Separator(cadre).pack(side="bottom", fill="x", pady=(10, 0))

        ttk.Label(cadre, text=t("conversations"), style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Button(cadre, text=t("nouvelle_conversation"), command=self.nouvelle_conversation,
                   style="Accent.TButton").pack(fill="x", pady=(0, 8))
        self.arbre_conv = ttk.Treeview(cadre, show="tree", selectmode="browse", columns=("n",))
        self.arbre_conv.column("#0", width=int(170 * self.echelle), stretch=True)
        self.arbre_conv.column("n", width=int(44 * self.echelle), stretch=False, anchor="e")
        self.arbre_conv.pack(fill="both", expand=True)
        self.arbre_conv.bind("<<TreeviewSelect>>", lambda e: self.changer_conversation())
        self.arbre_conv.bind("<Double-1>", lambda e: self.renommer_conversation())
        self.arbre_conv.bind("<F2>", lambda e: self.renommer_conversation())
        self.arbre_conv.bind("<Delete>", lambda e: self.fermer_conversation())
        self.arbre_conv.bind("<Button-3>", self.menu_conversation)
        return cadre

    def construire_elements(self, parent):
        t = self.t
        cadre = ttk.Frame(parent, padding=(0, 0, 10, 0))
        entete = ttk.Frame(cadre)
        entete.pack(fill="x", pady=(0, 8))
        self.titre_elements = ttk.Label(entete, style="Titre.TLabel")
        self.titre_elements.pack(side="left")
        self.bouton_basculer = ttk.Button(entete, text=t("ne_plus_masquer"), command=self.basculer_element,
                                          state="disabled")
        self.bouton_basculer.pack(side="right")
        zone = ttk.Frame(cadre)
        zone.pack(fill="both", expand=True)
        self.arbre = ttk.Treeview(zone, columns=("jeton", "type", "valeur", "nb"), show="headings",
                                  selectmode="browse")
        e = self.echelle
        for col, titre, largeur, etire, ancre in (
            ("jeton", t("col_jeton"), 110, False, "w"),
            ("type", t("col_type"), 170, False, "w"),
            ("valeur", t("col_valeur"), 200, True, "w"),
            ("nb", t("col_fois"), 50, False, "center"),
        ):
            self.arbre.heading(col, text=titre, anchor=ancre)
            self.arbre.column(col, width=int(largeur * e), minwidth=int(44 * e), stretch=etire, anchor=ancre)
        barre = ttk.Scrollbar(zone, command=self.arbre.yview)
        self.arbre.configure(yscrollcommand=barre.set)
        barre.pack(side="right", fill="y", padx=(4, 0))
        self.arbre.pack(side="left", fill="both", expand=True)
        self.arbre.bind("<<TreeviewSelect>>", lambda e: self.selection_element())
        self.arbre.bind("<Double-1>", lambda e: self.basculer_element())
        self.arbre.bind("<Button-3>", self.menu_element)
        ttk.Label(cadre, style="Aide.TLabel", text=t("aide_elements")).pack(anchor="w", pady=(6, 0))
        self.arbre_elements_couleurs()
        return cadre

    def construire_termes(self, parent):
        t = self.t
        cadre = ttk.Frame(parent, padding=(10, 0, 0, 0))
        self.titre_termes = ttk.Label(cadre, style="Titre.TLabel")
        self.titre_termes.pack(anchor="w", pady=(0, 8))

        self.termes = ListeTermes(self, cadre, self.ajouter_terme, self.supprimer_termes, hauteur=4)
        self.termes.pack(fill="both", expand=True)
        pied = ttk.Frame(cadre)
        pied.pack(fill="x", pady=(8, 0))
        ttk.Button(pied, text=t("supprimer"), command=self.supprimer_termes).pack(side="right")
        ttk.Button(pied, text=t("toujours_masquer"), command=self.rendre_permanents).pack(side="right", padx=(0, 8))
        ttk.Label(pied, style="Aide.TLabel", text=t("aide_clic_droit")).pack(side="left")
        return cadre

    def reconstruire(self):
        """Reconstruit l'interface (changement de langue), sans toucher aux conversations."""
        self.sauver_zones()
        for attente in self.attentes.values():
            self.root.after_cancel(attente)
        self.attentes = {}
        for enfant in self.root.winfo_children():
            enfant.destroy()
        self.construire()
        self.appliquer_theme(force=True)
        self.charger_zones()

    # --- mises à jour -----------------------------------------------------
    def message(self, texte):
        """Plus de barre d'état : les actions se voient directement dans la fenêtre."""

    def erreur(self, texte):
        """Erreur d'enregistrement : affichée une seule fois, pour ne pas répéter la même fenêtre."""
        if texte not in self.erreurs_vues:
            self.erreurs_vues.add(texte)
            messagebox.showwarning("IA-Anonymiser", texte, parent=self.root)

    def confirmer(self, bouton, cle):
        """Retour visuel sur un bouton : « Copié ! » pendant un instant."""
        bouton.configure(text=self.t("copie_ok"))
        self.root.after(1500, lambda: bouton.winfo_exists() and bouton.configure(text=self.t(cle)))

    def modifie(self, widget, action):
        if not widget.edit_modified():
            return
        widget.edit_modified(False)
        if action in self.attentes:
            self.root.after_cancel(self.attentes[action])
        delai = DELAI_MS if int(widget.index("end-1c").split(".")[0]) < 2000 else 4 * DELAI_MS
        self.attentes[action] = self.root.after(delai, action)

    def actualiser(self):
        self.attentes.pop(self.actualiser, None)
        res = self.moteur.anonymiser(self.source.lire(), self.termes_actifs(), self.options.types,
                                     self.options.motifs)
        self.resultat = res
        self.source.surligner(res.spans_source, "masque")
        self.sortie.ecrire(res.texte, res.spans_sortie, "jeton")
        self.remplir_elements(res)
        if self.source.lire().strip():
            self.message(self.t("msg_compte", r=sum(res.compte.values()), e=len(res.compte)))

    def actualiser_reponse(self):
        self.attentes.pop(self.actualiser_reponse, None)
        res = self.resultat_reponse = self.moteur.restaurer(self.reponse.lire())
        self.reponse.surligner(res.spans_source, "jeton")
        self.reponse.surligner(res.inconnus, "inconnu")
        self.restauree.ecrire(res.texte, res.spans_sortie, "jeton")
        if not self.reponse.lire().strip():
            return
        texte = self.t("msg_restaure", n=sum(res.compte.values()))
        if res.inconnus:
            texte += self.t("msg_inconnus", n=len(res.inconnus))
        self.message(texte)

    def libelle(self, type_, valeur):
        if type_ == "NOM" and valeur.casefold() in {p.casefold() for p in self.options.permanents}:
            return self.t("type_permanent")
        return self.t(f"type_{type_}")

    def remplir_elements(self, res):
        """Tous les éléments masqués de la conversation, y compris ceux des messages précédents."""
        selection = self.arbre.selection()
        self.arbre.delete(*self.arbre.get_children())
        presents = set(res.ordre)
        for jeton in res.ordre + [j for j in self.moteur.jetons() if j not in presents]:
            type_, valeur = self.moteur.info(jeton)
            exclu = jeton in self.moteur.exclus
            nb = res.ignores[jeton] if exclu else res.compte[jeton]
            tags = ("exclu",) if exclu else () if nb else ("absent",)
            self.arbre.insert("", "end", iid=jeton, tags=tags,
                              values=(jeton, self.libelle(type_, valeur) + (self.t("en_clair") if exclu else ""),
                                      normaliser(valeur), nb or "–"))
        garde = [s for s in selection if self.arbre.exists(s)]
        if garde:
            self.arbre.selection_set(garde)
        n = len(self.moteur.jetons())
        self.titre_elements.configure(text=self.t("elements", n=n))
        self.onglets.tab(2, text=self.t("onglet_elements", n=n))
        self.selection_element()

    def selection_element(self):
        selection = self.arbre.selection()
        self.source.texte.tag_remove("actif", "1.0", "end")
        if not selection:
            self.bouton_basculer.configure(state="disabled", text=self.t("ne_plus_masquer"))
            return
        jeton = selection[0]
        exclu = jeton in self.moteur.exclus
        self.bouton_basculer.configure(state="normal",
                                       text=self.t("masquer_a_nouveau" if exclu else "ne_plus_masquer"))
        spans = [s for s in (self.resultat.spans_source if self.resultat else []) if s[2] == jeton]
        self.source.surligner(spans, "actif")
        if spans:
            premier = self.source.texte.tag_nextrange("actif", "1.0")
            if premier:
                self.source.texte.see(premier[0])

    def maj_termes(self):
        self.termes.remplir(self.conv.termes)
        self.titre_termes.configure(text=self.t("termes_conv", n=len(self.conv.termes)))

    def maj_conversations(self):
        self.arbre_conv.delete(*self.arbre_conv.get_children())
        for i, c in enumerate(self.conversations):
            n = len(c.moteur.valide)
            self.arbre_conv.insert("", "end", iid=str(i), text=c.nom, values=(n or "",))
        self.arbre_conv.selection_set(str(self.courante))
        self.arbre_conv.see(str(self.courante))

    # --- conversations ----------------------------------------------------
    def sauver_zones(self):
        if self.conversations:
            self.conv.source = self.source.lire()
            self.conv.reponse = self.reponse.lire()

    def charger_zones(self):
        self.source.ecrire(self.conv.source)
        self.reponse.ecrire(self.conv.reponse)
        self.source.texte.edit_modified(False)
        self.reponse.texte.edit_modified(False)
        self.arbre.selection_remove(*self.arbre.selection())
        self.maj_termes()
        self.maj_conversations()
        self.actualiser()
        self.actualiser_reponse()
        self.root.title(f"IA-Anonymiser {VERSION} — {self.conv.nom}")

    def nouvelle_conversation(self):
        self.sauver_zones()
        self.numero += 1
        # La plus récente en haut de la liste
        self.conversations.insert(0, Conversation(self.t("nom_conversation", n=self.numero), self.t.langue))
        self.courante = 0
        self.charger_zones()
        self.onglets.select(0)
        self.message(self.t("msg_conversation_creee", c=self.conv.nom))
        self.sauvegarder()

    def changer_conversation(self):
        selection = self.arbre_conv.selection()
        if not selection or int(selection[0]) == self.courante:
            return
        self.sauver_zones()
        self.courante = int(selection[0])
        self.charger_zones()
        self.message(self.t("msg_conversation_choisie", c=self.conv.nom))

    def menu_conversation(self, evenement):
        ligne = self.arbre_conv.identify_row(evenement.y)
        if ligne:
            self.arbre_conv.selection_set(ligne)
            self.changer_conversation()
        t, menu = self.t, self.menu_conv
        menu.delete(0, "end")
        if ligne:
            menu.add_command(label=t("renommer"), command=self.renommer_conversation)
            menu.add_command(label=t("fermer"), command=self.fermer_conversation)
            menu.add_separator()
        menu.add_command(label=t("nouvelle_conversation").lstrip("+ "), command=self.nouvelle_conversation)
        menu.tk_popup(evenement.x_root, evenement.y_root)

    def renommer_conversation(self):
        nom = simpledialog.askstring(self.t("renommer_titre"), self.t("renommer_question"),
                                     initialvalue=self.conv.nom, parent=self.root)
        if nom and nom.strip():
            self.conv.nom = nom.strip()
            self.maj_conversations()
            self.root.title(f"IA-Anonymiser {VERSION} — {self.conv.nom}")
            self.sauvegarder()

    def fermer_conversation(self):
        if self.moteur.valide and not messagebox.askyesno(
                self.t("fermer_titre"), self.t("fermer_question", c=self.conv.nom), parent=self.root):
            return
        del self.conversations[self.courante]
        if not self.conversations:
            self.numero = 0
            self.nouvelle_conversation()
            return
        self.courante = min(self.courante, len(self.conversations) - 1)
        self.charger_zones()
        self.sauvegarder()

    def valider(self):
        self.moteur.valider()
        self.maj_conversations()
        if self.resultat:
            self.remplir_elements(self.resultat)
        self.sauvegarder()

    # --- conservation -----------------------------------------------------
    def reprendre_conversations(self):
        if not self.options.conserver:
            return 0
        try:
            donnees = stockage.charger_conversations()
        except Exception as e:
            messagebox.showwarning(self.t("illisible_titre"), self.t("illisible", e=e), parent=self.root)
            return 0
        if not donnees:
            return 0
        for d in donnees.get("conversations", []):
            try:
                self.conversations.append(Conversation.depuis_etat(d, self.t.langue))
            except (TypeError, ValueError, AttributeError):
                continue
        if not self.conversations:
            return 0
        self.courante = min(max(int(donnees.get("courante", 0)), 0), len(self.conversations) - 1)
        self.numero = max(int(donnees.get("numero", 0)), len(self.conversations))
        return len(self.conversations)

    def sauvegarder(self):
        if not self.options.conserver or not self.conversations:
            return
        self.sauver_zones()
        try:
            stockage.sauver_conversations({
                "version": 1, "courante": self.courante, "numero": self.numero,
                "conversations": [c.etat() for c in self.conversations]})
        except Exception as e:
            self.erreur(self.t("msg_erreur_sauvegarde", e=e))

    def sauvegarde_periodique(self):
        self.sauvegarder()
        self.root.after(SAUVEGARDE_MS, self.sauvegarde_periodique)

    def quitter(self):
        if self.options.conserver:
            self.sauvegarder()
        else:
            actives = [c for c in self.conversations if c.moteur.valide]
            if actives and not messagebox.askyesno(self.t("quitter_titre"),
                                                   self.t("quitter_question", n=len(actives)), parent=self.root):
                return
        self.root.destroy()

    # --- éléments et termes -----------------------------------------------
    def basculer_element(self, jeton=None):
        if jeton is None:
            selection = self.arbre.selection()
            if not selection:
                return
            jeton = selection[0]
        if jeton in self.moteur.exclus:
            self.moteur.exclus.discard(jeton)
        else:
            self.moteur.exclus.add(jeton)
        self.actualiser()

    def ajouter_terme(self, terme=None, permanent=False):
        terme = normaliser(self.termes.saisie() if terme is None else terme)
        if len(terme) < 2:
            self.message(self.t("msg_terme_court"))
            return
        if permanent:
            self.options.permanents = stockage.trier(self.options.permanents + [terme])
            self.sauver_options()
            self.message(self.t("msg_terme_permanent", t=terme))
        else:
            self.conv.termes = stockage.trier(self.conv.termes + [terme])
            self.maj_termes()
            self.message(self.t("msg_terme_conv", t=terme, c=self.conv.nom))
        self.moteur.reinclure("NOM", terme)
        self.actualiser()

    def supprimer_termes(self):
        retires = set(self.termes.selection())
        if not retires:
            self.message(self.t("msg_selection_termes"))
            return
        self.conv.termes = [t for t in self.conv.termes if t not in retires]
        self.maj_termes()
        self.actualiser()

    def rendre_permanents(self):
        choisis = self.termes.selection()
        if not choisis:
            self.message(self.t("msg_selection_termes"))
            return
        self.options.permanents = stockage.trier(self.options.permanents + choisis)
        self.conv.termes = [t for t in self.conv.termes if t not in choisis]
        self.sauver_options()
        self.maj_termes()
        self.actualiser()
        self.message(self.t("msg_rendus_permanents", n=len(choisis)))

    def selection_source(self):
        try:
            return normaliser(self.source.texte.get("sel.first", "sel.last"))
        except tk.TclError:
            return ""

    def masquer_selection(self, permanent=False):
        selection = self.selection_source()
        if not selection:
            self.message(self.t("msg_selection_mot"))
            return
        self.ajouter_terme(selection, permanent=permanent)

    def jeton_sous(self, zone, spans, evenement):
        """Jeton (ou valeur masquée) sous le pointeur, ou None."""
        if not spans:
            return None
        index = zone.texte.index(f"@{evenement.x},{evenement.y}")
        position = len(zone.texte.get("1.0", index))
        i = bisect.bisect_right([d for d, _, _ in spans], position) - 1
        if i >= 0 and spans[i][0] <= position < spans[i][1]:
            return spans[i][2]
        return None

    def ajouter_bascule(self, menu, jeton):
        """Entrée « Ne pas masquer » (ou « Masquer à nouveau ») pour un élément de la conversation."""
        info = self.moteur.info(jeton)
        if not info:
            return False
        valeur = normaliser(info[1])
        court = valeur if len(valeur) <= 40 else valeur[:37] + "…"
        cle = "menu_masquer_a_nouveau" if jeton in self.moteur.exclus else "menu_ne_pas_masquer"
        menu.add_command(label=self.t(cle, t=court, j=jeton), command=lambda: self.basculer_element(jeton))
        return True

    def menu_contextuel(self, evenement, zone, spans):
        t, texte, menu = self.t, zone.texte, self.menu
        menu.delete(0, "end")
        separer = False
        jeton = self.jeton_sous(zone, spans, evenement)
        if jeton:
            separer = self.ajouter_bascule(menu, jeton)
        try:
            selection = normaliser(texte.get("sel.first", "sel.last"))
        except tk.TclError:
            selection = ""
        if zone is self.source and len(selection) >= 2:
            court = selection if len(selection) <= 40 else selection[:37] + "…"
            menu.add_command(label=t("menu_masquer_conv", t=court), command=self.masquer_selection)
            menu.add_command(label=t("menu_toujours", t=court),
                             command=lambda: self.masquer_selection(permanent=True))
            separer = True
        if separer:
            menu.add_separator()
        if selection:
            menu.add_command(label=t("menu_copier"), command=lambda: texte.event_generate("<<Copy>>"))
        if not zone.lecture_seule:
            menu.add_command(label=t("menu_coller"), command=lambda: texte.event_generate("<<Paste>>"))
        menu.add_command(label=t("menu_tout"), command=lambda: texte.tag_add("sel", "1.0", "end-1c"))
        menu.tk_popup(evenement.x_root, evenement.y_root)

    def menu_element(self, evenement):
        ligne = self.arbre.identify_row(evenement.y)
        if not ligne:
            return
        self.arbre.selection_set(ligne)
        self.menu.delete(0, "end")
        if self.ajouter_bascule(self.menu, ligne):
            self.menu.tk_popup(evenement.x_root, evenement.y_root)

    # --- presse-papiers ---------------------------------------------------
    def vider(self, zone):
        zone.ecrire("")
        zone.texte.edit_modified(True)

    def coller(self, zone):
        try:
            texte = self.root.clipboard_get()
        except tk.TclError:
            self.message(self.t("msg_presse_papiers_vide"))
            return
        zone.ecrire(texte)
        zone.texte.edit_modified(True)

    def ecrire_presse_papiers(self, texte):
        self.root.clipboard_clear()
        self.root.clipboard_append(texte)
        self.root.update()

    def copier_sortie(self):
        texte = self.sortie.lire()
        if not texte.strip():
            self.message(self.t("msg_rien_copier"))
            return
        self.valider()
        if self.options.consigne and self.resultat and self.resultat.compte:
            texte = self.consigne() + texte
        self.ecrire_presse_papiers(texte)
        self.confirmer(self.bouton_copier_ia, "copier_ia")

    def copier_restauree(self):
        texte = self.restauree.lire()
        if not texte.strip():
            self.message(self.t("msg_rien_restaurer"))
            return
        self.ecrire_presse_papiers(texte)
        self.confirmer(self.bouton_copier, "copier")

    # --- fenêtres ---------------------------------------------------------
    def fenetre(self, titre):
        fen = tk.Toplevel(self.root)
        fen.title(titre)
        fen.transient(self.root)
        fen.withdraw()
        return fen

    def afficher(self, fen, focus=None):
        fen.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - fen.winfo_reqwidth()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - fen.winfo_reqheight()) // 3
        fen.geometry(f"+{max(0, x)}+{max(0, y)}")
        fen.deiconify()
        barre_de_titre(fen, self.theme_applique == "sombre")
        fen.bind("<Escape>", lambda e: fen.destroy())
        fen.grab_set()
        (focus or fen).focus_set()

    def sauver_options(self):
        try:
            self.options.sauver()
        except OSError as e:
            self.erreur(self.t("msg_erreur_options", e=e))

    def ouvrir_options(self):
        t, e = self.t, self.echelle
        fen = self.fenetre(t("opt_titre"))
        self.fenetre_options = fen
        cadre = ttk.Frame(fen, padding=20)
        cadre.pack(fill="both", expand=True)
        onglets = ttk.Notebook(cadre)
        onglets.pack(fill="both", expand=True)
        self.onglets_options = onglets
        largeur_texte = int(520 * e)

        # Détection
        o = ttk.Frame(onglets, padding=18)
        onglets.add(o, text=t("opt_detection"))
        ttk.Label(o, text=t("opt_masquer_auto"), style="Section.TLabel").pack(anchor="w")
        ttk.Label(o, text=t("opt_masquer_aide"), style="Aide.TLabel", wraplength=largeur_texte,
                  justify="left").pack(anchor="w", pady=(2, 10))
        grille = ttk.Frame(o)
        grille.pack(fill="x")
        cases = {}
        for i, type_ in enumerate(TYPES_AUTO):
            cases[type_] = tk.BooleanVar(value=type_ in self.options.types)
            case = ttk.Frame(grille, padding=(0, 4, 24, 4))
            case.grid(row=i // 2, column=i % 2, sticky="w")
            ttk.Checkbutton(case, text=t(f"type_{type_}"), variable=cases[type_]).pack(anchor="w")
            ttk.Label(case, text=t("opt_exemple", e=EXEMPLES[type_]), style="Aide.TLabel").pack(
                anchor="w", padx=(int(28 * e), 0))

        # Termes permanents
        o = ttk.Frame(onglets, padding=18)
        onglets.add(o, text=t("opt_termes"))
        ttk.Label(o, text=t("opt_termes_titre"), style="Section.TLabel").pack(anchor="w")
        ttk.Label(o, text=t("opt_termes_aide"), style="Aide.TLabel", wraplength=largeur_texte,
                  justify="left").pack(anchor="w", pady=(2, 10))
        permanents = list(self.options.permanents)

        def ajouter():
            terme = liste.saisie()
            if len(terme) >= 2:
                permanents[:] = stockage.trier(permanents + [terme])
                liste.remplir(permanents)

        def supprimer():
            retires = set(liste.selection())
            permanents[:] = [x for x in permanents if x not in retires]
            liste.remplir(permanents)

        liste = ListeTermes(self, o, ajouter, supprimer, hauteur=8)
        liste.pack(fill="both", expand=True)
        liste.remplir(permanents)
        ttk.Button(o, text=t("opt_supprimer_selection"), command=supprimer).pack(anchor="e", pady=(8, 0))

        # Motifs personnalisés
        o = ttk.Frame(onglets, padding=18)
        onglets.add(o, text=t("opt_motifs"))
        ttk.Label(o, text=t("opt_motifs_titre"), style="Section.TLabel").pack(anchor="w")
        ttk.Label(o, text=t("opt_motifs_aide"), style="Aide.TLabel", wraplength=largeur_texte,
                  justify="left").pack(anchor="w", pady=(2, 10))
        motifs = list(self.options.motifs)
        retour_motif = ttk.Label(o, style="Aide.TLabel", wraplength=largeur_texte, justify="left")

        def ajouter_motif():
            motif = liste_motifs.champ.get().strip()
            if not motif:
                return
            try:
                rx = compiler_motif(motif)
            except Exception as exc:
                retour_motif.configure(text=t("opt_motif_invalide", e=exc))
                return
            liste_motifs.champ.delete(0, "end")
            if motif not in motifs:
                motifs.append(motif)
            liste_motifs.remplir(motifs)
            n = sum(1 for _ in rx.finditer(self.source.lire()))
            retour_motif.configure(text=t("opt_motif_trouve", m=motif, n=n))

        def supprimer_motifs():
            retires = set(liste_motifs.selection())
            motifs[:] = [x for x in motifs if x not in retires]
            liste_motifs.remplir(motifs)

        liste_motifs = ListeTermes(self, o, ajouter_motif, supprimer_motifs, hauteur=7)
        liste_motifs.pack(fill="both", expand=True)
        liste_motifs.remplir(motifs)
        retour_motif.pack(anchor="w", pady=(8, 0))
        self.lien(o, t("opt_motifs_site"), "https://regex101.com/?flavor=python")
        ttk.Button(o, text=t("opt_supprimer_selection"), command=supprimer_motifs).pack(anchor="e", pady=(8, 0))

        # Consigne pour l'IA
        o = ttk.Frame(onglets, padding=18)
        onglets.add(o, text=t("opt_consigne"))
        avec_consigne = tk.BooleanVar(value=self.options.consigne)
        ttk.Checkbutton(o, text=t("opt_consigne_activer"), variable=avec_consigne).pack(anchor="w")
        ttk.Label(o, text=t("opt_consigne_aide"), style="Aide.TLabel", wraplength=largeur_texte,
                  justify="left").pack(anchor="w", pady=(2, 10))
        zone_consigne = Zone(self, o, "")
        zone_consigne.entete.pack_forget()
        zone_consigne.texte.configure(height=7, width=60)
        zone_consigne.pack(fill="both", expand=True)
        zone_consigne.colorer(self.palette)
        zone_consigne.ecrire(self.options.consigne_texte or CONSIGNES[t.langue])
        ttk.Button(o, text=t("opt_consigne_defaut"),
                   command=lambda: zone_consigne.ecrire(CONSIGNES[t.langue])).pack(anchor="e", pady=(8, 0))

        # Général
        o = ttk.Frame(onglets, padding=18)
        onglets.add(o, text=t("opt_general"))
        ttk.Label(o, text=t("opt_langue"), style="Section.TLabel").pack(anchor="w")
        langues = [("auto", t("opt_langue_auto")), ("fr", "Français"), ("en", "English")]
        choix_langue = ttk.Combobox(o, state="readonly", values=[n for _, n in langues], width=34)
        choix_langue.current([c for c, _ in langues].index(self.options.langue))
        choix_langue.pack(anchor="w", pady=(6, 16))
        ttk.Label(o, text=t("opt_theme"), style="Section.TLabel").pack(anchor="w")
        theme = tk.StringVar(value=self.options.theme)
        ligne = ttk.Frame(o)
        ligne.pack(anchor="w", pady=(6, 16))
        for valeur, cle in (("auto", "opt_theme_auto"), ("clair", "opt_theme_clair"), ("sombre", "opt_theme_sombre")):
            ttk.Radiobutton(ligne, text=t(cle), value=valeur, variable=theme).pack(side="left", padx=(0, 18))
        conserver = tk.BooleanVar(value=self.options.conserver)
        ttk.Checkbutton(o, text=t("opt_conserver"), variable=conserver).pack(anchor="w")
        ttk.Label(o, text=t("opt_conserver_aide"), style="Aide.TLabel", wraplength=largeur_texte,
                  justify="left").pack(anchor="w", padx=(int(28 * e), 0), pady=(2, 8))

        def effacer():
            stockage.effacer_conversations()
            self.message(t("opt_effacees"))

        ttk.Button(o, text=t("opt_effacer_conversations"), command=effacer).pack(
            anchor="w", padx=(int(28 * e), 0))

        def enregistrer():
            ancienne_langue = self.t.langue
            self.options.types = {k for k, v in cases.items() if v.get()}
            self.options.permanents = stockage.trier(permanents)
            self.options.motifs = stockage.motifs_valides(motifs)
            self.options.consigne = avec_consigne.get()
            texte = zone_consigne.lire().strip()
            self.options.consigne_texte = None if not texte or texte == CONSIGNES[t.langue] else texte
            self.options.langue = langues[choix_langue.current()][0]
            self.options.theme = theme.get()
            self.options.conserver = conserver.get()
            self.sauver_options()
            fen.destroy()
            if self.options.conserver:
                self.sauvegarder()
            else:
                stockage.effacer_conversations()
            nouvelle_langue = self.options.langue_effective()
            if nouvelle_langue != ancienne_langue:
                self.t = Traducteur(nouvelle_langue)
                for c in self.conversations:
                    c.moteur.langue = nouvelle_langue
                self.reconstruire()
            else:
                self.appliquer_theme()
                self.actualiser()
            self.message(self.t("msg_options_ok"))

        boutons = ttk.Frame(cadre)
        boutons.pack(fill="x", pady=(16, 0))
        ttk.Button(boutons, text=t("enregistrer"), command=enregistrer, style="Accent.TButton").pack(side="right")
        ttk.Button(boutons, text=t("annuler"), command=fen.destroy).pack(side="right", padx=(0, 8))
        self.afficher(fen)

    def lien(self, parent, texte, url):
        etiquette = ttk.Label(parent, text=texte, style="Lien.TLabel", cursor="hand2")
        etiquette.bind("<Button-1>", lambda e: webbrowser.open(url))
        etiquette.pack(anchor="w", pady=2)
        return etiquette

    def ouvrir_a_propos(self):
        t, e = self.t, self.echelle
        fen = self.fenetre(t("ap_titre"))
        self.fenetre_a_propos = fen
        cadre = ttk.Frame(fen, padding=24)
        cadre.pack(fill="both", expand=True)
        largeur = int(500 * e)

        haut = ttk.Frame(cadre)
        haut.pack(fill="x")
        if self.icone_entete:
            ttk.Label(haut, image=self.icone_entete).pack(side="left", padx=(0, 14))
        titres = ttk.Frame(haut)
        titres.pack(side="left")
        ttk.Label(titres, text="IA-Anonymiser", style="Entete.TLabel").pack(anchor="w")
        ttk.Label(titres, text=t("ap_version", v=VERSION), style="Aide.TLabel").pack(anchor="w")
        ttk.Label(cadre, text=t("ap_description"), wraplength=largeur, justify="left").pack(anchor="w", pady=(14, 14))

        verif = ttk.Frame(cadre)
        verif.pack(fill="x")
        bouton = ttk.Button(verif, text=t("ap_verifier"))
        bouton.pack(side="left")
        resultat = ttk.Label(verif, style="Aide.TLabel")
        resultat.pack(side="left", padx=(12, 0))
        telecharger = ttk.Label(cadre, text=t("ap_telecharger"), style="Lien.TLabel", cursor="hand2")
        ttk.Label(cadre, text=t("ap_verifier_aide"), style="Aide.TLabel", wraplength=largeur,
                  justify="left").pack(anchor="w", pady=(6, 0))

        def afficher_resultat(tag, url, erreur):
            if not fen.winfo_exists():
                return
            bouton.configure(state="normal")
            if erreur:
                resultat.configure(text=t("ap_erreur", e=erreur))
                return
            installee, publiee = version_tuple(VERSION), version_tuple(tag)
            if installee and publiee and publiee > installee:
                resultat.configure(text=t("ap_nouvelle", v=tag))
                telecharger.bind("<Button-1>", lambda ev: webbrowser.open(url))
                telecharger.pack(anchor="w", pady=(6, 0), after=verif)
            elif installee:
                resultat.configure(text=t("ap_a_jour"))
            else:
                resultat.configure(text=t("ap_derniere", v=tag))

        def verifier():
            bouton.configure(state="disabled")
            resultat.configure(text=t("ap_recherche"))

            def tache():
                tag = url = erreur = ""
                try:
                    requete = urllib.request.Request(API_DERNIERE, headers={
                        "User-Agent": f"IA-Anonymiser/{VERSION}", "Accept": "application/vnd.github+json"})
                    with urllib.request.urlopen(requete, timeout=10) as r:
                        d = json.load(r)
                    tag, url = d.get("tag_name", ""), d.get("html_url") or DEPOT + "/releases/latest"
                except Exception as exc:
                    erreur = str(getattr(exc, "reason", exc))
                self.root.after(0, afficher_resultat, tag, url, erreur)

            threading.Thread(target=tache, daemon=True).start()

        bouton.configure(command=verifier)

        for titre, contenu in ((t("ap_liens"), None), (t("ap_donnees"), t("ap_donnees_texte")),
                               (t("ap_licence"), t("ap_licence_texte"))):
            ttk.Label(cadre, text=titre, style="Section.TLabel").pack(anchor="w", pady=(18, 4))
            if contenu:
                ttk.Label(cadre, text=contenu, wraplength=largeur, justify="left").pack(anchor="w")
            else:
                self.lien(cadre, t("ap_source"), DEPOT)
                self.lien(cadre, t("ap_releases"), DEPOT + "/releases")
                self.lien(cadre, t("ap_probleme"), DEPOT + "/issues")

        def support():
            infos = (f"IA-Anonymiser {VERSION}\n{platform.platform()}\nPython {platform.python_version()}, "
                     f"Tk {tk.TkVersion}\nLangue : {self.t.langue} ({self.options.langue}), "
                     f"thème : {self.theme_applique} ({self.options.theme}), "
                     f"Sun Valley : {'oui' if sv_ttk else 'non'}\n"
                     f"Types : {', '.join(sorted(self.options.types))}\n"
                     f"Conversations conservées : {'oui' if self.options.conserver else 'non'}")
            self.ecrire_presse_papiers(infos)
            info.configure(text=t("ap_support_copie"))

        bas = ttk.Frame(cadre)
        bas.pack(fill="x", pady=(22, 0))
        ttk.Button(bas, text=t("ap_support"), command=support).pack(side="left")
        info = ttk.Label(bas, style="Aide.TLabel")
        info.pack(side="left", padx=(10, 0))
        ttk.Button(bas, text=t("fermer"), command=fen.destroy, style="Accent.TButton").pack(side="right")
        self.afficher(fen)


# --- captures d'écran (intégration continue) -----------------------------------
DEMO = {
    "fr": (
        "Bonjour,\n\nPeux-tu rédiger une relance pour Jean Dupont (Acme SAS) ? Il n'a pas réglé la facture "
        "F-2026-118. Ses coordonnées : jean.dupont@acme-sas.fr, 06 12 34 56 78.\n"
        "Le virement est attendu sur FR76 3000 6000 0112 3456 7890 189.\n\nMerci, Claire Martin",
        "Voici une proposition :\n\nBonjour [NOM_1],\n\nSauf erreur de notre part, la facture F-2026-118 reste "
        "impayée. Merci d'effectuer le virement sur [IBAN_1].\n\nCordialement,\n[NOM_3]",
        "Relance facture", "Panne serveur paie",
        "Le serveur srv-paie01.acme.local (10.12.4.21, MAC 00:1A:2B:3C:4D:5E) ne répond plus depuis la mise à "
        "jour (INC-2026-4471). Compte ACME\\svc-paie, profil C:\\Users\\svc-paie\\AppData, "
        "chaîne de connexion Server=sql01;User Id=paie;Password=Paie2026!;\n"
        "Le fichier de log est joint : erreur.log. Peux-tu m'aider ?\n\nMerci, Claire Martin",
    ),
    "en": (
        "Hello,\n\nCould you write a reminder for John Smith (Acme Ltd)? He hasn't paid invoice F-2026-118. "
        "His details: john.smith@acme-ltd.com, +44 20 7946 0958.\n"
        "Payment is expected on GB29 NWBK 6016 1331 9268 19.\n\nThanks, Claire Martin",
        "Here is a draft:\n\nDear [NAME_1],\n\nAccording to our records, invoice F-2026-118 is still unpaid. "
        "Please make the transfer to [IBAN_1].\n\nBest regards,\n[NAME_3]",
        "Invoice reminder", "Payroll server down",
        "Server srv-pay01.acme.local (10.12.4.21, MAC 00:1A:2B:3C:4D:5E) stopped responding after the update. "
        "(INC-2026-4471). Account ACME\\svc-pay, profile C:\\Users\\svc-pay\\AppData, "
        "connection string Server=sql01;User Id=pay;Password=Pay2026!;\n"
        "The log file is attached: error.log. Can you help?\n\nThanks, Claire Martin",
    ),
}


def capture(app, chemin):
    """Remplit la fenêtre d'exemples fictifs et photographie les écrans principaux."""
    app.sauvegarder = lambda: None
    app.options.sauver = lambda: None

    def remplir():
        texte, reponse, nom1, nom2, serveurs = DEMO[app.t.langue]
        app.options.permanents = ["Acme SAS", "Acme Ltd", "Claire Martin"]
        app.options.motifs = [r"PC-\d{4}", r"INC-\d{4}-\d+"]
        app.conversations, app.numero = [], 0
        app.nouvelle_conversation()
        app.conv.nom = nom1
        app.conv.termes = ["Jean Dupont" if app.t.langue == "fr" else "John Smith"]
        app.charger_zones()
        app.source.ecrire(texte)
        app.actualiser()
        app.valider()
        app.reponse.ecrire(reponse)
        app.actualiser_reponse()
        app.nouvelle_conversation()
        app.conv.nom = nom2
        app.source.ecrire(serveurs)
        app.actualiser()
        app.maj_conversations()

    def photo(fenetre, nom):
        from PIL import ImageGrab
        app.root.update()
        x, y = fenetre.winfo_rootx(), fenetre.winfo_rooty()
        w, h = fenetre.winfo_width(), fenetre.winfo_height()
        ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.path.join(chemin, nom))

    def conversation(i, onglet):
        app.arbre_conv.selection_set(str(i))
        app.changer_conversation()
        app.onglets.select(onglet)

    def theme(nom):
        app.options.theme = nom
        app.appliquer_theme()

    def langue(code):
        app.t = Traducteur(code)
        app.reconstruire()
        remplir()

    def options(onglet):
        app.ouvrir_options()
        app.onglets_options.select(onglet)

    def gros_log():
        lignes = [f"2026-11-10 12:{i % 60:02d}:01 srv{i % 40}.acme.local [10.0.{i % 250}.{i % 200}] GET "
                  f"/api/v1/items?id={i} 200 user{i % 50}@acme.fr" for i in range(3000)]
        import time
        debut = time.perf_counter()
        app.source.ecrire("\n".join(lignes))
        app.actualiser()
        app.root.update()
        with open(os.path.join(chemin, "duree-gros-log.txt"), "w", encoding="utf-8") as f:
            f.write(f"{len(lignes)} lignes : {time.perf_counter() - debut:.2f} s\n")

    etapes = [
        lambda: photo(app.root, "demarrage.png"),
        lambda: (app.onglets.select(1), app.root.update()), lambda: photo(app.root, "demarrage-onglet2.png"),
        lambda: (app.onglets.select(0), gros_log()), lambda: photo(app.root, "gros-log.png"),
        lambda: theme("clair"), lambda: langue("fr"),
        lambda: photo(app.root, "clair-anonymiser.png"),
        lambda: conversation(1, 1), lambda: photo(app.root, "clair-restaurer.png"),
        lambda: conversation(1, 0), lambda: photo(app.root, "clair-relance.png"),
        lambda: conversation(1, 2), lambda: photo(app.root, "clair-elements.png"),
        lambda: options(0), lambda: photo(app.fenetre_options, "options-detection.png"),
        lambda: app.onglets_options.select(2), lambda: photo(app.fenetre_options, "options-motifs.png"),
        lambda: app.onglets_options.select(3), lambda: photo(app.fenetre_options, "options-consigne.png"),
        lambda: app.onglets_options.select(4), lambda: photo(app.fenetre_options, "options-general.png"),
        lambda: app.fenetre_options.destroy(),
        app.ouvrir_a_propos, lambda: photo(app.fenetre_a_propos, "a-propos.png"),
        lambda: app.fenetre_a_propos.destroy(),
        lambda: (theme("sombre"), conversation(0, 0)), lambda: photo(app.root, "sombre-anonymiser.png"),
        lambda: conversation(1, 1), lambda: photo(app.root, "sombre-restaurer.png"),
        lambda: langue("en"), lambda: conversation(1, 1), lambda: photo(app.root, "en-sombre-restaurer.png"),
        lambda: (theme("clair"), conversation(0, 0)), lambda: photo(app.root, "en-clair-anonymiser.png"),
        app.root.destroy,
    ]

    def suivante(i=0):
        etapes[i]()
        if i + 1 < len(etapes):
            app.root.after(700, suivante, i + 1)

    app.root.after(1500, suivante)


def main():
    capture_dans = sys.argv[2] if len(sys.argv) == 3 and sys.argv[1] == "--capture" else None
    if capture_dans:
        import tempfile
        os.environ["APPDATA"] = tempfile.mkdtemp()  # ne rien lire ni écrire dans la vraie configuration
        os.makedirs(capture_dans, exist_ok=True)
    activer_dpi()
    root = tk.Tk()
    app = Application(root)
    if capture_dans:
        capture(app, capture_dans)
    root.mainloop()


if __name__ == "__main__":
    main()
