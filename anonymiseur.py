"""IA-Anonymiser : interface graphique.

À gauche : les conversations ouvertes, chacune avec ses propres jetons.
Onglet 1 : texte original / version anonymisée. Onglet 2 : réponse de l'IA / vraies valeurs.
En bas : les éléments masqués et les termes de la conversation.
Options : types détectés, termes toujours masqués (nom de l'entreprise…), consigne pour l'IA.
"""
import json
import os
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, simpledialog, ttk

from moteur import EXEMPLES, JETON_RE, LIBELLES, TYPES_AUTO, Anonymiseur

try:
    from version import VERSION
except ImportError:
    VERSION = "dev"

CONSIGNE = (
    "Consigne : ce texte contient des jetons comme [NOM_1] ou [EMAIL_1] qui remplacent des "
    "données confidentielles. Reprends-les exactement tels quels dans ta réponse, sans les "
    "modifier, les traduire ni les compléter.\n\n"
)
DELAI_MS = 250
SONDE_MS = 700

COULEURS = {
    "masque": "#fff1a8",
    "actif": "#ffc94d",
    "jeton": "#d3f2dc",
    "inconnu": "#ffd4d4",
}


def activer_dpi():
    """Évite le texte flou sur les écrans Windows mis à l'échelle (125 %, 150 %…)."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def dossier_config():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    dossier = os.path.join(base, "IA-Anonymiser")
    os.makedirs(dossier, exist_ok=True)
    return dossier


def normaliser(terme):
    return " ".join(terme.split())


def trier(termes):
    vus, sortie = set(), []
    for t in termes:
        t = normaliser(t)
        if len(t) >= 2 and t.casefold() not in vus:
            vus.add(t.casefold())
            sortie.append(t)
    return sorted(sortie, key=str.casefold)


class Options:
    """Réglages enregistrés dans %APPDATA%\\IA-Anonymiser\\options.json."""

    def __init__(self):
        self.chemin = os.path.join(dossier_config(), "options.json")
        self.types = set(TYPES_AUTO)
        self.permanents = []
        self.consigne = True
        self.charger()

    def charger(self):
        try:
            with open(self.chemin, encoding="utf-8") as f:
                d = json.load(f)
            self.types = {t for t in d.get("types", TYPES_AUTO) if t in TYPES_AUTO}
            self.permanents = trier(d.get("permanents", []))
            self.consigne = bool(d.get("consigne", True))
        except (OSError, ValueError):
            # Reprise de la liste de termes de la version 1.1
            try:
                with open(os.path.join(dossier_config(), "termes.txt"), encoding="utf-8") as f:
                    self.permanents = trier(f)
            except OSError:
                pass

    def sauver(self):
        with open(self.chemin, "w", encoding="utf-8") as f:
            json.dump({"types": sorted(self.types), "permanents": self.permanents,
                       "consigne": self.consigne}, f, ensure_ascii=False, indent=2)


class Conversation:
    def __init__(self, nom):
        self.nom = nom
        self.moteur = Anonymiseur()
        self.termes = []
        self.source = ""
        self.reponse = ""


class Zone(ttk.Frame):
    """Zone de texte avec un titre, des boutons et une barre de défilement."""

    def __init__(self, parent, titre, police, lecture_seule=False, marge=(0, 0, 0, 0)):
        super().__init__(parent, padding=marge)
        self.entete = ttk.Frame(self)
        self.entete.pack(fill="x", pady=(0, 6))
        ttk.Label(self.entete, text=titre, style="Titre.TLabel").pack(side="left")

        cadre = ttk.Frame(self)
        cadre.pack(fill="both", expand=True)
        self.texte = tk.Text(cadre, wrap="word", font=police, undo=not lecture_seule,
                             relief="solid", borderwidth=1, padx=10, pady=8,
                             highlightthickness=0, spacing1=2, spacing3=2)
        barre = ttk.Scrollbar(cadre, command=self.texte.yview)
        self.texte.configure(yscrollcommand=barre.set)
        barre.pack(side="right", fill="y")
        self.texte.pack(side="left", fill="both", expand=True)
        for nom, couleur in COULEURS.items():
            self.texte.tag_configure(nom, background=couleur)
        self.texte.tag_raise("sel")

        self.lecture_seule = lecture_seule
        if lecture_seule:
            self.texte.configure(state="disabled", background="#f6f7f9")

    def bouton(self, texte, commande):
        """Ajoute un bouton à droite du titre (le premier ajouté est le plus à droite)."""
        b = ttk.Button(self.entete, text=texte, command=commande)
        b.pack(side="right", padx=(6, 0))
        return b

    def lire(self):
        return self.texte.get("1.0", "end-1c")

    def ecrire(self, contenu, spans=(), tag=None):
        position = self.texte.yview()[0]
        self.texte.configure(state="normal")
        self.texte.delete("1.0", "end")
        self.texte.insert("1.0", contenu)
        if tag:
            self.surligner(spans, tag)
        self.texte.yview_moveto(position)
        if self.lecture_seule:
            self.texte.configure(state="disabled")
        else:
            self.texte.edit_reset()

    def surligner(self, spans, tag):
        self.texte.tag_remove(tag, "1.0", "end")
        for debut, fin, _ in spans:
            self.texte.tag_add(tag, f"1.0+{debut}c", f"1.0+{fin}c")


class ListeTermes(ttk.Frame):
    """Champ de saisie + liste de termes + boutons."""

    def __init__(self, parent, police, ajouter, supprimer):
        super().__init__(parent)
        ligne = ttk.Frame(self)
        ligne.pack(fill="x", pady=(0, 6))
        self.champ = ttk.Entry(ligne, font=police)
        self.champ.pack(side="left", fill="x", expand=True)
        self.champ.bind("<Return>", lambda e: ajouter())
        ttk.Button(ligne, text="Ajouter", command=ajouter).pack(side="left", padx=(6, 0))

        zone = ttk.Frame(self)
        zone.pack(fill="both", expand=True)
        self.liste = tk.Listbox(zone, font=police, selectmode="extended", activestyle="none",
                                relief="solid", borderwidth=1, highlightthickness=0, exportselection=False)
        barre = ttk.Scrollbar(zone, command=self.liste.yview)
        self.liste.configure(yscrollcommand=barre.set)
        barre.pack(side="right", fill="y")
        self.liste.pack(side="left", fill="both", expand=True)
        self.liste.bind("<Delete>", lambda e: supprimer())

    def remplir(self, termes):
        self.liste.delete(0, "end")
        for t in termes:
            self.liste.insert("end", t)

    def selection(self):
        return [self.liste.get(i) for i in self.liste.curselection()]

    def saisie(self):
        texte = normaliser(self.champ.get())
        self.champ.delete(0, "end")
        return texte


class Application:
    def __init__(self, root):
        self.root = root
        self.options = Options()
        self.conversations = []
        self.courante = 0
        self.numero = 0
        self.resultat = None
        self.attentes = {}
        self.dernier_presse_papiers = None

        root.title(f"IA-Anonymiser {VERSION}")
        self.dimensionner()
        self.styles()
        self.construire()
        self.nouvelle_conversation()
        self.message("Collez votre texte à gauche : la version anonymisée apparaît à droite.")
        root.protocol("WM_DELETE_WINDOW", self.quitter)
        self.sonder()

    @property
    def conv(self):
        return self.conversations[self.courante]

    @property
    def moteur(self):
        return self.conv.moteur

    def termes_actifs(self):
        return self.options.permanents + self.conv.termes

    # --- apparence --------------------------------------------------------
    def dimensionner(self):
        """Grande fenêtre centrée, adaptée à l'écran et à sa mise à l'échelle."""
        self.echelle = echelle = max(1.0, self.root.winfo_fpixels("1i") / 96)
        ecran_l, ecran_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        largeur = min(int(1440 * echelle), int(ecran_l * 0.92))
        hauteur = min(int(880 * echelle), int(ecran_h * 0.88))
        x, y = (ecran_l - largeur) // 2, max(0, (ecran_h - hauteur) // 2 - int(20 * echelle))
        self.root.geometry(f"{largeur}x{hauteur}+{x}+{y}")
        self.root.minsize(min(largeur, int(1000 * echelle)), min(hauteur, int(620 * echelle)))
        if largeur < 1200 * echelle:
            try:
                self.root.state("zoomed")  # petit écran : plein écran (Windows)
            except tk.TclError:
                pass

    def styles(self):
        style = ttk.Style()
        for theme in ("vista", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        base = tkfont.nametofont("TkDefaultFont")
        base.configure(size=10)
        famille = "Segoe UI" if sys.platform == "win32" else base.actual("family")
        base.configure(family=famille)
        self.police = tkfont.Font(family=famille, size=11)
        style.configure("Titre.TLabel", font=(famille, 11, "bold"))
        style.configure("Aide.TLabel", foreground="#666")
        style.configure("Statut.TLabel", foreground="#444")
        style.configure("TNotebook.Tab", padding=(14, 6))
        style.configure("Treeview", rowheight=self.police.metrics("linespace") + 10, font=self.police)
        style.configure("Treeview.Heading", font=(famille, 10, "bold"))

    # --- construction -----------------------------------------------------
    def construire(self):
        root = self.root

        barre = ttk.Frame(root, padding=(12, 10, 12, 4))
        barre.pack(fill="x")
        ttk.Button(barre, text="Options…", command=self.ouvrir_options).pack(side="left")
        self.auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(barre, text="Mode automatique du presse-papiers", variable=self.auto,
                        command=self.basculer_auto).pack(side="left", padx=(16, 0))
        self.resume_options = ttk.Label(barre, style="Aide.TLabel")
        self.resume_options.pack(side="right")

        self.statut = ttk.Label(root, style="Statut.TLabel", padding=(12, 4, 12, 8), anchor="w")
        self.statut.pack(side="bottom", fill="x")

        lateral = ttk.Panedwindow(root, orient="horizontal")
        lateral.pack(fill="both", expand=True, padx=12, pady=(4, 0))
        lateral.add(self.construire_conversations(lateral), weight=0)

        principal = ttk.Panedwindow(lateral, orient="vertical")
        lateral.add(principal, weight=1)

        self.onglets = ttk.Notebook(principal)
        principal.add(self.onglets, weight=3)

        # Onglet 1 : anonymiser
        o1 = ttk.Frame(self.onglets, padding=10)
        self.onglets.add(o1, text="1. Anonymiser mon texte")
        p1 = ttk.Panedwindow(o1, orient="horizontal")
        p1.pack(fill="both", expand=True)
        self.source = Zone(p1, "Texte original", self.police, marge=(0, 0, 8, 0))
        self.source.bouton("Effacer", lambda: self.source.ecrire(""))
        self.source.bouton("Coller", lambda: self.coller(self.source))
        self.sortie = Zone(p1, "Texte à envoyer à l'IA", self.police, lecture_seule=True, marge=(8, 0, 0, 0))
        self.sortie.bouton("Copier pour l'IA", self.copier_sortie)
        p1.add(self.source, weight=1)
        p1.add(self.sortie, weight=1)

        # Onglet 2 : restaurer
        o2 = ttk.Frame(self.onglets, padding=10)
        self.onglets.add(o2, text="2. Restaurer la réponse de l'IA")
        p2 = ttk.Panedwindow(o2, orient="horizontal")
        p2.pack(fill="both", expand=True)
        self.reponse = Zone(p2, "Réponse de l'IA (collez-la ici)", self.police, marge=(0, 0, 8, 0))
        self.reponse.bouton("Effacer", lambda: self.reponse.ecrire(""))
        self.reponse.bouton("Coller", lambda: self.coller(self.reponse))
        self.restauree = Zone(p2, "Réponse avec les vraies valeurs", self.police, lecture_seule=True,
                              marge=(8, 0, 0, 0))
        self.restauree.bouton("Copier", self.copier_restauree)
        p2.add(self.reponse, weight=1)
        p2.add(self.restauree, weight=1)

        # Bas : éléments masqués + termes de la conversation
        bas = ttk.Frame(principal, padding=(0, 10, 0, 0))
        principal.add(bas, weight=2)
        pb = ttk.Panedwindow(bas, orient="horizontal")
        pb.pack(fill="both", expand=True)
        pb.add(self.construire_elements(pb), weight=3)
        pb.add(self.construire_termes(pb), weight=2)

        # Événements
        self.source.texte.bind("<<Modified>>", lambda e: self.modifie(self.source.texte, self.actualiser))
        self.reponse.texte.bind("<<Modified>>",
                                lambda e: self.modifie(self.reponse.texte, self.actualiser_reponse))
        self.sortie.texte.bind("<<Copy>>", lambda e: self.valider(), add="+")
        self.menu = tk.Menu(root, tearoff=0)
        self.source.texte.bind("<Button-3>", self.menu_contextuel)
        self.source.texte.bind("<Control-m>", lambda e: (self.masquer_selection(), "break")[1])
        self.maj_resume_options()

    def construire_conversations(self, parent):
        cadre = ttk.Frame(parent, padding=(0, 0, 10, 0), width=int(220 * self.echelle))
        ttk.Label(cadre, text="Conversations", style="Titre.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Button(cadre, text="+ Nouvelle conversation", command=self.nouvelle_conversation).pack(
            fill="x", pady=(0, 6))
        zone = ttk.Frame(cadre)
        zone.pack(fill="both", expand=True)
        self.liste_conv = tk.Listbox(zone, font=self.police, activestyle="none", exportselection=False,
                                     relief="solid", borderwidth=1, highlightthickness=0, width=20)
        self.liste_conv.pack(fill="both", expand=True)
        self.liste_conv.bind("<<ListboxSelect>>", lambda e: self.changer_conversation())
        self.liste_conv.bind("<Double-1>", lambda e: self.renommer_conversation())
        pied = ttk.Frame(cadre)
        pied.pack(fill="x", pady=(6, 0))
        ttk.Button(pied, text="Renommer", command=self.renommer_conversation).pack(
            side="left", fill="x", expand=True)
        ttk.Button(pied, text="Fermer", command=self.fermer_conversation).pack(
            side="left", fill="x", expand=True, padx=(6, 0))
        ttk.Label(cadre, style="Aide.TLabel", wraplength=int(200 * self.echelle), justify="left",
                  text="Une conversation par discussion avec l'IA : chacune garde ses propres jetons.").pack(
            anchor="w", pady=(8, 0))
        return cadre

    def construire_elements(self, parent):
        cadre = ttk.Frame(parent, padding=(0, 0, 8, 0))
        entete = ttk.Frame(cadre)
        entete.pack(fill="x", pady=(0, 6))
        self.titre_elements = ttk.Label(entete, text="Éléments masqués", style="Titre.TLabel")
        self.titre_elements.pack(side="left")
        self.bouton_basculer = ttk.Button(entete, text="Ne plus masquer", command=self.basculer_element,
                                          state="disabled")
        self.bouton_basculer.pack(side="right")

        zone = ttk.Frame(cadre)
        zone.pack(fill="both", expand=True)
        colonnes = ("jeton", "type", "valeur", "nb")
        self.arbre = ttk.Treeview(zone, columns=colonnes, show="headings", selectmode="browse")
        for col, titre, largeur, etire, ancre in (
            ("jeton", "Jeton", 110, False, "w"),
            ("type", "Type", 160, False, "w"),
            ("valeur", "Valeur d'origine", 200, True, "w"),
            ("nb", "Fois", 50, False, "center"),
        ):
            self.arbre.heading(col, text=titre, anchor=ancre)
            self.arbre.column(col, width=largeur, minwidth=50, stretch=etire, anchor=ancre)
        self.arbre.tag_configure("exclu", foreground="#9a9a9a")
        barre = ttk.Scrollbar(zone, command=self.arbre.yview)
        self.arbre.configure(yscrollcommand=barre.set)
        barre.pack(side="right", fill="y")
        self.arbre.pack(side="left", fill="both", expand=True)
        self.arbre.bind("<<TreeviewSelect>>", lambda e: self.selection_element())
        self.arbre.bind("<Double-1>", lambda e: self.basculer_element())
        ttk.Label(cadre, style="Aide.TLabel",
                  text="Double-cliquez sur une ligne pour masquer ou ne plus masquer cet élément.").pack(
            anchor="w", pady=(6, 0))
        return cadre

    def construire_termes(self, parent):
        cadre = ttk.Frame(parent, padding=(8, 0, 0, 0))
        self.titre_termes = ttk.Label(cadre, text="Termes de cette conversation", style="Titre.TLabel")
        self.titre_termes.pack(anchor="w", pady=(0, 2))
        self.aide_termes = ttk.Label(cadre, style="Aide.TLabel")
        self.aide_termes.pack(anchor="w", pady=(0, 4))
        self.termes = ListeTermes(cadre, self.police, self.ajouter_terme, self.supprimer_termes)
        self.termes.pack(fill="both", expand=True)
        pied = ttk.Frame(cadre)
        pied.pack(fill="x", pady=(6, 0))
        ttk.Button(pied, text="Supprimer", command=self.supprimer_termes).pack(side="right")
        ttk.Button(pied, text="Toujours masquer", command=self.rendre_permanents).pack(side="right", padx=(0, 6))
        ttk.Label(pied, style="Aide.TLabel", text="Clic droit sur un mot → Masquer (Ctrl+M)").pack(side="left")
        return cadre

    # --- mises à jour -----------------------------------------------------
    def message(self, texte):
        self.statut.configure(text=texte)

    def maj_resume_options(self):
        n = len(self.options.permanents)
        self.resume_options.configure(
            text=f"{len(self.options.types)}/{len(TYPES_AUTO)} types détectés · {n} terme(s) toujours masqué(s)")
        if hasattr(self, "aide_termes"):
            self.aide_termes.configure(
                text=f"Les {n} terme(s) permanents (entreprise…) se règlent dans Options.")

    def modifie(self, widget, action):
        if not widget.edit_modified():
            return
        widget.edit_modified(False)
        if action in self.attentes:
            self.root.after_cancel(self.attentes[action])
        self.attentes[action] = self.root.after(DELAI_MS, action)

    def actualiser(self):
        self.attentes.pop(self.actualiser, None)
        res = self.moteur.anonymiser(self.source.lire(), self.termes_actifs(), self.options.types)
        self.resultat = res
        self.source.surligner(res.spans_source, "masque")
        self.sortie.ecrire(res.texte, res.spans_sortie, "jeton")
        self.remplir_elements(res)
        if self.source.lire().strip():
            self.message(f"{sum(res.compte.values())} remplacement(s), {len(res.compte)} élément(s) différent(s). "
                         "Relisez le texte de droite, puis cliquez sur « Copier pour l'IA ».")

    def actualiser_reponse(self):
        self.attentes.pop(self.actualiser_reponse, None)
        res = self.moteur.restaurer(self.reponse.lire())
        self.reponse.surligner(res.spans_source, "jeton")
        self.reponse.surligner(res.inconnus, "inconnu")
        self.restauree.ecrire(res.texte, res.spans_sortie, "jeton")
        if not self.reponse.lire().strip():
            return
        texte = f"{sum(res.compte.values())} jeton(s) restauré(s)."
        if res.inconnus:
            texte += (f" {len(res.inconnus)} jeton(s) inconnu(s), en rouge : la réponse vient sans doute "
                      "d'une autre conversation.")
        self.message(texte)

    def remplir_elements(self, res):
        selection = self.arbre.selection()
        self.arbre.delete(*self.arbre.get_children())
        permanents = {t.casefold() for t in self.options.permanents}
        for jeton in res.ordre:
            type_, valeur = self.moteur.info(jeton)
            exclu = jeton in self.moteur.exclus
            libelle = "Terme permanent" if type_ == "NOM" and valeur.casefold() in permanents else LIBELLES[type_]
            nb = res.ignores[jeton] if exclu else res.compte[jeton]
            self.arbre.insert("", "end", iid=jeton, tags=("exclu",) if exclu else (),
                              values=(jeton, libelle + (" (en clair)" if exclu else ""),
                                      normaliser(valeur), nb))
        garde = [s for s in selection if self.arbre.exists(s)]
        if garde:
            self.arbre.selection_set(garde)
        self.titre_elements.configure(text=f"Éléments masqués ({len(res.compte)})")
        self.selection_element()

    def selection_element(self):
        selection = self.arbre.selection()
        self.source.texte.tag_remove("actif", "1.0", "end")
        if not selection:
            self.bouton_basculer.configure(state="disabled", text="Ne plus masquer")
            return
        jeton = selection[0]
        exclu = jeton in self.moteur.exclus
        self.bouton_basculer.configure(state="normal", text="Masquer à nouveau" if exclu else "Ne plus masquer")
        spans = [s for s in (self.resultat.spans_source if self.resultat else []) if s[2] == jeton]
        self.source.surligner(spans, "actif")
        if spans:
            self.source.texte.see(f"1.0+{spans[0][0]}c")

    def maj_termes(self):
        self.termes.remplir(self.conv.termes)
        self.titre_termes.configure(text=f"Termes de cette conversation ({len(self.conv.termes)})")

    def maj_conversations(self):
        self.liste_conv.delete(0, "end")
        for c in self.conversations:
            n = len(c.moteur.valide)
            self.liste_conv.insert("end", f"{c.nom}  ·  {n} jeton(s)" if n else c.nom)
        self.liste_conv.selection_clear(0, "end")
        self.liste_conv.selection_set(self.courante)
        self.liste_conv.see(self.courante)

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
        self.conversations.append(Conversation(f"Conversation {self.numero}"))
        self.courante = len(self.conversations) - 1
        self.charger_zones()
        self.onglets.select(0)
        self.message(f"{self.conv.nom} créée : collez votre premier texte à gauche.")

    def changer_conversation(self):
        selection = self.liste_conv.curselection()
        if not selection or selection[0] == self.courante:
            return
        self.sauver_zones()
        self.courante = selection[0]
        self.charger_zones()
        self.message(f"{self.conv.nom} : les réponses collées seront restaurées avec ses jetons.")

    def renommer_conversation(self):
        nom = simpledialog.askstring("Renommer", "Nom de la conversation :", initialvalue=self.conv.nom,
                                     parent=self.root)
        if nom and nom.strip():
            self.conv.nom = nom.strip()
            self.maj_conversations()
            self.root.title(f"IA-Anonymiser {VERSION} — {self.conv.nom}")

    def fermer_conversation(self):
        if self.moteur.valide and not messagebox.askyesno(
            "Fermer la conversation",
            f"Les correspondances de « {self.conv.nom} » seront oubliées : les réponses de l'IA à cette "
            "conversation ne pourront plus être restaurées.\n\nContinuer ?",
        ):
            return
        del self.conversations[self.courante]
        if not self.conversations:
            self.numero = 0
            self.nouvelle_conversation()
            return
        self.courante = min(self.courante, len(self.conversations) - 1)
        self.charger_zones()

    def valider(self):
        self.moteur.valider()
        self.maj_conversations()

    # --- éléments et termes -----------------------------------------------
    def basculer_element(self):
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
            self.message("Un terme doit contenir au moins deux caractères.")
            return
        if permanent:
            self.options.permanents = trier(self.options.permanents + [terme])
            self.sauver_options()
            self.message(f"« {terme} » sera toujours masqué, dans toutes les conversations.")
        else:
            self.conv.termes = trier(self.conv.termes + [terme])
            self.maj_termes()
            self.message(f"« {terme} » sera masqué dans {self.conv.nom}.")
        self.moteur.reinclure("NOM", terme)
        self.actualiser()

    def supprimer_termes(self):
        retires = set(self.termes.selection())
        if not retires:
            self.message("Sélectionnez d'abord un ou plusieurs termes dans la liste.")
            return
        self.conv.termes = [t for t in self.conv.termes if t not in retires]
        self.maj_termes()
        self.actualiser()

    def rendre_permanents(self):
        choisis = self.termes.selection()
        if not choisis:
            self.message("Sélectionnez d'abord un ou plusieurs termes à toujours masquer.")
            return
        self.options.permanents = trier(self.options.permanents + choisis)
        self.conv.termes = [t for t in self.conv.termes if t not in choisis]
        self.sauver_options()
        self.maj_termes()
        self.actualiser()
        self.message(f"{len(choisis)} terme(s) ajouté(s) aux termes toujours masqués (voir Options).")

    def selection_source(self):
        try:
            return normaliser(self.source.texte.get("sel.first", "sel.last"))
        except tk.TclError:
            return ""

    def masquer_selection(self, permanent=False):
        selection = self.selection_source()
        if not selection:
            self.message("Sélectionnez d'abord un mot dans le texte original.")
            return
        self.ajouter_terme(selection, permanent=permanent)

    def menu_contextuel(self, evenement):
        self.menu.delete(0, "end")
        selection = self.selection_source()
        if len(selection) >= 2:
            court = selection if len(selection) <= 40 else selection[:37] + "…"
            self.menu.add_command(label=f"Masquer « {court} » dans cette conversation",
                                  command=self.masquer_selection)
            self.menu.add_command(label=f"Toujours masquer « {court} »",
                                  command=lambda: self.masquer_selection(permanent=True))
            self.menu.add_separator()
            self.menu.add_command(label="Copier", command=lambda: self.source.texte.event_generate("<<Copy>>"))
        self.menu.add_command(label="Coller", command=lambda: self.source.texte.event_generate("<<Paste>>"))
        self.menu.add_command(label="Tout sélectionner",
                              command=lambda: self.source.texte.tag_add("sel", "1.0", "end-1c"))
        self.menu.tk_popup(evenement.x_root, evenement.y_root)

    # --- options ----------------------------------------------------------
    def sauver_options(self):
        try:
            self.options.sauver()
        except OSError as e:
            self.message(f"Impossible d'enregistrer les options : {e}")
        self.maj_resume_options()

    def ouvrir_options(self):
        fen = tk.Toplevel(self.root)
        fen.title("Options")
        fen.transient(self.root)
        self.fenetre_options = fen
        cadre = ttk.Frame(fen, padding=18)
        cadre.pack(fill="both", expand=True)

        colonnes = ttk.Frame(cadre)
        colonnes.pack(fill="both", expand=True)

        gauche = ttk.Frame(colonnes)
        gauche.pack(side="left", fill="y", anchor="n")
        ttk.Label(gauche, text="Masquer automatiquement", style="Titre.TLabel").pack(anchor="w")
        ttk.Label(gauche, style="Aide.TLabel", text="Décochez ce que vous voulez laisser en clair.").pack(
            anchor="w", pady=(0, 8))
        cases = {}
        for type_ in TYPES_AUTO:
            cases[type_] = tk.BooleanVar(value=type_ in self.options.types)
            ligne = ttk.Frame(gauche)
            ligne.pack(fill="x", pady=2)
            ttk.Checkbutton(ligne, text=LIBELLES[type_], variable=cases[type_]).pack(anchor="w")
            ttk.Label(ligne, text=f"ex. {EXEMPLES[type_]}", style="Aide.TLabel").pack(
                anchor="w", padx=(int(24 * self.echelle), 0))
        ttk.Separator(gauche).pack(fill="x", pady=12)
        consigne = tk.BooleanVar(value=self.options.consigne)
        ttk.Checkbutton(gauche, text="Ajouter une consigne pour l'IA en copiant", variable=consigne).pack(anchor="w")
        ttk.Label(gauche, style="Aide.TLabel", wraplength=int(320 * self.echelle), justify="left",
                  text="Demande à l'IA de garder les jetons tels quels : la restauration est plus fiable.").pack(
            anchor="w", padx=(int(24 * self.echelle), 0))

        droite = ttk.Frame(colonnes, padding=(int(28 * self.echelle), 0, 0, 0))
        droite.pack(side="left", fill="both", expand=True)
        ttk.Label(droite, text="Termes toujours masqués", style="Titre.TLabel").pack(anchor="w")
        ttk.Label(droite, style="Aide.TLabel", wraplength=int(340 * self.echelle), justify="left",
                  text="Nom de l'entreprise, des clients, des collègues, adresses… Ils sont masqués dans "
                       "toutes les conversations et restent enregistrés.").pack(anchor="w", pady=(0, 8))
        permanents = list(self.options.permanents)

        def ajouter():
            t = liste.saisie()
            if len(t) >= 2:
                permanents[:] = trier(permanents + [t])
                liste.remplir(permanents)

        def supprimer():
            retires = set(liste.selection())
            permanents[:] = [t for t in permanents if t not in retires]
            liste.remplir(permanents)

        liste = ListeTermes(droite, self.police, ajouter, supprimer)
        liste.pack(fill="both", expand=True)
        liste.liste.configure(height=12, width=32)
        liste.remplir(permanents)
        ttk.Button(droite, text="Supprimer la sélection", command=supprimer).pack(anchor="e", pady=(6, 0))

        def enregistrer():
            self.options.types = {t for t, v in cases.items() if v.get()}
            self.options.permanents = trier(permanents)
            self.options.consigne = consigne.get()
            self.sauver_options()
            fen.destroy()
            self.actualiser()
            self.message("Options enregistrées.")

        boutons = ttk.Frame(cadre)
        boutons.pack(fill="x", pady=(16, 0))
        ttk.Button(boutons, text="Enregistrer", command=enregistrer).pack(side="right")
        ttk.Button(boutons, text="Annuler", command=fen.destroy).pack(side="right", padx=(0, 6))
        fen.bind("<Escape>", lambda e: fen.destroy())

        fen.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - fen.winfo_reqwidth()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - fen.winfo_reqheight()) // 3
        fen.geometry(f"+{max(0, x)}+{max(0, y)}")
        fen.grab_set()
        liste.champ.focus_set()

    # --- presse-papiers ---------------------------------------------------
    def coller(self, zone):
        texte = self.lire_presse_papiers()
        if texte is None:
            self.message("Le presse-papiers ne contient pas de texte.")
            return
        zone.ecrire(texte)
        zone.texte.edit_modified(True)

    def copier_sortie(self):
        texte = self.sortie.lire()
        if not texte.strip():
            self.message("Rien à copier : collez d'abord un texte à gauche.")
            return
        self.valider()
        if self.options.consigne and self.resultat and self.resultat.compte:
            texte = CONSIGNE + texte
        self.ecrire_presse_papiers(texte)
        self.message("Copié. Collez-le dans la conversation avec l'IA, puis collez sa réponse dans l'onglet 2.")

    def copier_restauree(self):
        texte = self.restauree.lire()
        if not texte.strip():
            self.message("Rien à copier : collez d'abord la réponse de l'IA à gauche.")
            return
        self.ecrire_presse_papiers(texte)
        self.message("Réponse avec les vraies valeurs copiée.")

    def lire_presse_papiers(self):
        try:
            return self.root.clipboard_get()
        except tk.TclError:
            return None

    def ecrire_presse_papiers(self, texte):
        self.root.clipboard_clear()
        self.root.clipboard_append(texte)
        self.root.update()
        self.dernier_presse_papiers = texte

    def basculer_auto(self):
        self.dernier_presse_papiers = self.lire_presse_papiers()
        if self.auto.get():
            self.message("Mode automatique : tout texte copié est anonymisé, et toute réponse contenant des "
                         "jetons est restaurée avec la conversation sélectionnée.")
        else:
            self.message("Mode automatique désactivé.")

    def sonder(self):
        if self.auto.get():
            texte = self.lire_presse_papiers()
            if texte and texte != self.dernier_presse_papiers:
                if JETON_RE.search(texte):
                    self.reponse.ecrire(texte)
                    self.actualiser_reponse()
                    self.onglets.select(1)
                    self.ecrire_presse_papiers(self.restauree.lire())
                    self.message(f"Réponse restaurée dans le presse-papiers ({self.conv.nom}).")
                else:
                    self.source.ecrire(texte)
                    self.actualiser()
                    self.onglets.select(0)
                    self.copier_sortie()
                    self.message(f"Texte anonymisé dans le presse-papiers ({self.conv.nom}) : collez-le dans l'IA.")
        self.root.after(SONDE_MS, self.sonder)

    def quitter(self):
        actives = [c for c in self.conversations if c.moteur.valide]
        if actives and not messagebox.askyesno(
            "Quitter",
            f"Les correspondances de {len(actives)} conversation(s) seront perdues : les réponses de l'IA "
            "ne pourront plus être restaurées.\n\nQuitter quand même ?",
        ):
            return
        self.root.destroy()


DEMO = (
    "Bonjour,\n\nPeux-tu rédiger une relance pour Jean Dupont (Acme SAS) ? Il n'a pas réglé la "
    "facture F-2026-118. Ses coordonnées : jean.dupont@acme-sas.fr, 06 12 34 56 78.\n"
    "Le virement est attendu sur FR76 3000 6000 0112 3456 7890 189.\n\nMerci, Claire Martin"
)
DEMO_SERVEURS = (
    "Le serveur srv-paie01.acme.local (10.12.4.21, MAC 00:1A:2B:3C:4D:5E) ne répond plus depuis la "
    "mise à jour. Le proxy proxy.acme.local redirige vers intranet.acme.fr.\n"
    "Le fichier de log est joint : erreur.log. Peux-tu m'aider à diagnostiquer ?\n\nMerci, Claire Martin"
)


def capture(app, chemin):
    """Mode réservé à l'intégration continue : remplit la fenêtre d'exemples fictifs et la photographie."""
    app.options.permanents = ["Acme SAS", "Claire Martin"]
    app.options.sauver = lambda: None  # ne rien écrire sur la machine de capture
    app.maj_resume_options()
    app.conv.nom = "Relance facture"
    app.conv.termes = ["Jean Dupont"]
    app.maj_termes()
    app.source.ecrire(DEMO)
    app.actualiser()
    app.valider()
    app.reponse.ecrire("Voici une proposition :\n\nBonjour [NOM_1],\n\nSauf erreur de notre part, la facture "
                       "F-2026-118 reste impayée. Merci d'effectuer le virement sur [IBAN_1].\n\n"
                       "Cordialement,\n[NOM_3]")
    app.actualiser_reponse()
    app.nouvelle_conversation()
    app.conv.nom = "Panne serveur paie"
    app.source.ecrire(DEMO_SERVEURS)
    app.actualiser()
    app.maj_conversations()

    def photo(fenetre, nom):
        from PIL import ImageGrab
        app.root.update()
        x, y = fenetre.winfo_rootx(), fenetre.winfo_rooty()
        w, h = fenetre.winfo_width(), fenetre.winfo_height()
        ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.path.join(chemin, nom))

    etapes = [
        lambda: photo(app.root, "onglet1.png"),
        lambda: (app.liste_conv.selection_clear(0, "end"), app.liste_conv.selection_set(0),
                 app.changer_conversation(), app.onglets.select(1)),
        lambda: photo(app.root, "onglet2.png"),
        app.ouvrir_options,
        lambda: photo(app.fenetre_options, "options.png"),
        app.root.destroy,
    ]

    def suivante(i=0):
        etapes[i]()
        if i + 1 < len(etapes):
            app.root.after(800, suivante, i + 1)

    app.root.after(1500, suivante)


def main():
    activer_dpi()
    root = tk.Tk()
    app = Application(root)
    if len(sys.argv) == 3 and sys.argv[1] == "--capture":
        os.makedirs(sys.argv[2], exist_ok=True)
        capture(app, sys.argv[2])
    root.mainloop()


if __name__ == "__main__":
    main()
