"""IA-Anonymiser : interface graphique.

Onglet 1 : texte original à gauche, version anonymisée à droite.
Onglet 2 : réponse de l'IA à gauche, réponse avec les vraies valeurs à droite.
En bas : les éléments masqués et la liste des termes personnalisés.
"""
import os
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from moteur import JETON_RE, LIBELLES, Anonymiseur

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


def fichier_termes():
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    dossier = os.path.join(base, "IA-Anonymiser")
    os.makedirs(dossier, exist_ok=True)
    return os.path.join(dossier, "termes.txt")


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

    def surligner(self, spans, tag):
        self.texte.tag_remove(tag, "1.0", "end")
        for debut, fin, _ in spans:
            self.texte.tag_add(tag, f"1.0+{debut}c", f"1.0+{fin}c")


class Application:
    def __init__(self, root):
        self.root = root
        self.moteur = Anonymiseur()
        self.chemin_termes = fichier_termes()
        self.termes = self.charger_termes()
        self.resultat = None
        self.attentes = {}
        self.dernier_presse_papiers = None

        root.title(f"IA-Anonymiser {VERSION}")
        self.dimensionner()
        self.styles()
        self.construire()
        self.maj_liste()
        self.actualiser()
        self.message("Collez votre texte à gauche : la version anonymisée apparaît à droite.")
        self.sonder()

    # --- apparence --------------------------------------------------------
    def dimensionner(self):
        """Grande fenêtre centrée, adaptée à l'écran et à sa mise à l'échelle."""
        echelle = max(1.0, self.root.winfo_fpixels("1i") / 96)
        ecran_l, ecran_h = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        largeur = min(int(1320 * echelle), int(ecran_l * 0.92))
        hauteur = min(int(860 * echelle), int(ecran_h * 0.88))
        x, y = (ecran_l - largeur) // 2, max(0, (ecran_h - hauteur) // 2 - int(20 * echelle))
        self.root.geometry(f"{largeur}x{hauteur}+{x}+{y}")
        self.root.minsize(min(largeur, int(900 * echelle)), min(hauteur, int(600 * echelle)))
        if largeur < 1100 * echelle:
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
        ttk.Button(barre, text="Nouvelle conversation", command=self.nouvelle_conversation).pack(side="left")
        self.consigne = tk.BooleanVar(value=True)
        ttk.Checkbutton(barre, text="Ajouter une consigne pour l'IA en copiant",
                        variable=self.consigne).pack(side="left", padx=(16, 0))
        self.auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(barre, text="Mode automatique du presse-papiers", variable=self.auto,
                        command=self.basculer_auto).pack(side="left", padx=(16, 0))

        self.statut = ttk.Label(root, style="Statut.TLabel", padding=(12, 4, 12, 8), anchor="w")
        self.statut.pack(side="bottom", fill="x")

        principal = ttk.Panedwindow(root, orient="vertical")
        principal.pack(fill="both", expand=True, padx=12, pady=(4, 0))

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

        # Bas : éléments masqués + termes
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
        self.sortie.texte.bind("<<Copy>>", lambda e: self.moteur.valider(), add="+")
        self.menu = tk.Menu(root, tearoff=0)
        self.source.texte.bind("<Button-3>", self.menu_contextuel)
        self.source.texte.bind("<Control-m>", lambda e: (self.masquer_selection(), "break")[1])

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
            ("jeton", "Jeton", 120, False, "w"),
            ("type", "Type", 170, False, "w"),
            ("valeur", "Valeur d'origine", 300, True, "w"),
            ("nb", "Fois", 60, False, "center"),
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
        self.titre_termes = ttk.Label(cadre, text="Termes à masquer", style="Titre.TLabel")
        self.titre_termes.pack(anchor="w", pady=(0, 6))

        ligne = ttk.Frame(cadre)
        ligne.pack(fill="x", pady=(0, 6))
        self.champ = ttk.Entry(ligne, font=self.police)
        self.champ.pack(side="left", fill="x", expand=True)
        self.champ.bind("<Return>", lambda e: self.ajouter_terme())
        ttk.Button(ligne, text="Ajouter", command=self.ajouter_terme).pack(side="left", padx=(6, 0))

        zone = ttk.Frame(cadre)
        zone.pack(fill="both", expand=True)
        self.liste = tk.Listbox(zone, font=self.police, selectmode="extended", activestyle="none",
                                relief="solid", borderwidth=1, highlightthickness=0)
        barre = ttk.Scrollbar(zone, command=self.liste.yview)
        self.liste.configure(yscrollcommand=barre.set)
        barre.pack(side="right", fill="y")
        self.liste.pack(side="left", fill="both", expand=True)
        self.liste.bind("<Delete>", lambda e: self.supprimer_termes())

        pied = ttk.Frame(cadre)
        pied.pack(fill="x", pady=(6, 0))
        ttk.Button(pied, text="Supprimer la sélection", command=self.supprimer_termes).pack(side="right")
        ttk.Label(pied, style="Aide.TLabel",
                  text="Astuce : sélectionnez un mot dans le texte original,\npuis clic droit → Masquer (ou Ctrl+M).").pack(
            side="left")
        return cadre

    # --- mises à jour -----------------------------------------------------
    def message(self, texte):
        self.statut.configure(text=texte)

    def modifie(self, widget, action):
        if not widget.edit_modified():
            return
        widget.edit_modified(False)
        if action in self.attentes:
            self.root.after_cancel(self.attentes[action])
        self.attentes[action] = self.root.after(DELAI_MS, action)

    def actualiser(self):
        self.attentes.pop(self.actualiser, None)
        res = self.moteur.anonymiser(self.source.lire(), self.termes)
        self.resultat = res
        self.source.surligner(res.spans_source, "masque")
        self.sortie.ecrire(res.texte, res.spans_sortie, "jeton")
        self.remplir_elements(res)
        n = sum(res.compte.values())
        if self.source.lire().strip():
            self.message(f"{n} remplacement(s), {len(res.compte)} élément(s) différent(s). "
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
            texte += (f" {len(res.inconnus)} jeton(s) inconnu(s), en rouge : ils viennent sans doute "
                      "d'une autre conversation ou d'une session fermée.")
        self.message(texte)

    def remplir_elements(self, res):
        selection = self.arbre.selection()
        self.arbre.delete(*self.arbre.get_children())
        for jeton in res.ordre:
            type_, valeur = self.moteur.info(jeton)
            exclu = jeton in self.moteur.exclus
            nb = res.ignores[jeton] if exclu else res.compte[jeton]
            self.arbre.insert("", "end", iid=jeton, tags=("exclu",) if exclu else (),
                              values=(jeton, LIBELLES[type_] + (" (en clair)" if exclu else ""),
                                      " ".join(valeur.split()), nb))
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

    def maj_liste(self):
        self.liste.delete(0, "end")
        for terme in self.termes:
            self.liste.insert("end", terme)
        self.titre_termes.configure(text=f"Termes à masquer ({len(self.termes)}) : noms, entreprises, adresses…")

    # --- actions ----------------------------------------------------------
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

    def ajouter_terme(self, terme=None):
        depuis_champ = terme is None
        terme = " ".join((self.champ.get() if depuis_champ else terme).split())
        if len(terme) < 2:
            self.message("Un terme doit contenir au moins deux caractères.")
            return
        if terme.casefold() not in {t.casefold() for t in self.termes}:
            self.termes.append(terme)
            self.termes.sort(key=str.casefold)
            self.sauver_termes()
            self.maj_liste()
        self.moteur.reinclure("NOM", terme)
        if depuis_champ:
            self.champ.delete(0, "end")
        self.actualiser()
        self.message(f"« {terme} » sera masqué dans tous vos textes.")

    def supprimer_termes(self):
        indices = self.liste.curselection()
        if not indices:
            self.message("Sélectionnez d'abord un ou plusieurs termes dans la liste.")
            return
        retires = {self.liste.get(i) for i in indices}
        self.termes = [t for t in self.termes if t not in retires]
        self.sauver_termes()
        self.maj_liste()
        self.actualiser()

    def masquer_selection(self):
        try:
            selection = self.source.texte.get("sel.first", "sel.last")
        except tk.TclError:
            self.message("Sélectionnez d'abord un mot dans le texte original.")
            return
        self.ajouter_terme(selection)

    def menu_contextuel(self, evenement):
        self.menu.delete(0, "end")
        try:
            selection = " ".join(self.source.texte.get("sel.first", "sel.last").split())
        except tk.TclError:
            selection = ""
        if len(selection) >= 2:
            court = selection if len(selection) <= 40 else selection[:37] + "…"
            self.menu.add_command(label=f"Masquer « {court} »", command=self.masquer_selection)
            self.menu.add_separator()
            self.menu.add_command(label="Copier", command=lambda: self.source.texte.event_generate("<<Copy>>"))
        self.menu.add_command(label="Coller", command=lambda: self.source.texte.event_generate("<<Paste>>"))
        self.menu.add_command(label="Tout sélectionner",
                              command=lambda: self.source.texte.tag_add("sel", "1.0", "end-1c"))
        self.menu.tk_popup(evenement.x_root, evenement.y_root)

    def coller(self, zone):
        texte = self.lire_presse_papiers()
        if texte is None:
            self.message("Le presse-papiers ne contient pas de texte.")
            return
        zone.ecrire(texte)

    def copier_sortie(self):
        texte = self.sortie.lire()
        if not texte.strip():
            self.message("Rien à copier : collez d'abord un texte à gauche.")
            return
        self.moteur.valider()
        if self.consigne.get() and self.resultat and self.resultat.compte:
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

    def nouvelle_conversation(self):
        if self.moteur.valide and not messagebox.askyesno(
            "Nouvelle conversation",
            "Les correspondances actuelles seront oubliées : les réponses à vos messages précédents "
            "ne pourront plus être restaurées.\n\nVos termes à masquer sont conservés. Continuer ?",
        ):
            return
        self.moteur.reinitialiser()
        for zone in (self.source, self.sortie, self.reponse, self.restauree):
            zone.ecrire("")
        self.actualiser()
        self.message("Nouvelle conversation : les jetons repartent de 1.")

    # --- presse-papiers ---------------------------------------------------
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
            self.message("Mode automatique : tout texte copié est anonymisé, et toute réponse "
                         "contenant des jetons est restaurée, directement dans le presse-papiers.")
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
                    self.message("Réponse restaurée dans le presse-papiers.")
                else:
                    self.source.ecrire(texte)
                    self.actualiser()
                    self.onglets.select(0)
                    self.copier_sortie()
                    self.message("Texte anonymisé dans le presse-papiers : collez-le dans l'IA.")
        self.root.after(SONDE_MS, self.sonder)

    # --- termes enregistrés -----------------------------------------------
    def charger_termes(self):
        try:
            with open(self.chemin_termes, encoding="utf-8") as f:
                return sorted({" ".join(l.split()) for l in f if l.strip()}, key=str.casefold)
        except OSError:
            return []

    def sauver_termes(self):
        try:
            with open(self.chemin_termes, "w", encoding="utf-8") as f:
                f.write("\n".join(self.termes) + "\n")
        except OSError as e:
            self.message(f"Impossible d'enregistrer les termes : {e}")


DEMO = (
    "Bonjour,\n\nPeux-tu rédiger une relance pour Jean Dupont (Acme SAS) ? Il n'a pas réglé la "
    "facture F-2026-118. Ses coordonnées : jean.dupont@acme-sas.fr, 06 12 34 56 78.\n"
    "Le virement est attendu sur FR76 3000 6000 0112 3456 7890 189.\n\nMerci, Claire Martin"
)


def capture(app, chemin):
    """Mode réservé à l'intégration continue : remplit la fenêtre d'un exemple et la photographie."""
    app.termes = ["Jean Dupont", "Acme SAS", "Claire Martin"]
    app.maj_liste()
    app.source.ecrire(DEMO)
    app.actualiser()

    def onglet2():
        app.moteur.valider()
        app.reponse.ecrire("Voici une proposition :\n\nBonjour [NOM_1],\n\nSauf erreur de notre part, la facture "
                           "F-2026-118 reste impayée. Merci d'effectuer le virement sur [IBAN_1].\n\n"
                           "Cordialement,\n[NOM_3]")
        app.actualiser_reponse()
        app.onglets.select(1)

    def photo(nom, ensuite):
        from PIL import ImageGrab
        app.root.update()
        x, y = app.root.winfo_rootx(), app.root.winfo_rooty()
        w, h = app.root.winfo_width(), app.root.winfo_height()
        ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.path.join(chemin, nom))
        ensuite()

    app.root.after(1500, lambda: photo("onglet1.png", lambda: (
        onglet2(), app.root.after(1000, lambda: photo("onglet2.png", app.root.destroy)))))


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
