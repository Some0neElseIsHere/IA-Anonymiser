"""Scénario de bout en bout : pilote la vraie interface d'IA-Anonymiser comme un utilisateur.

Usage : python tests/scenario_gui.py <phase 1|2> <dossier de sortie>
- Phase 1 : premier lancement, conversations, collage, copie pour l'IA, restauration, jetons
  personnalisés, rapport, épinglage, langue, thème, gros log, fermeture.
- Phase 2 : relance (même %APPDATA%) : tout doit avoir été conservé.

Les fenêtres modales (confirmations, choix de fichier, renommage) sont simulées. Chaque étape est
vérifiée ; le résultat est écrit dans resultats-phase<N>.txt et le code de sortie vaut 1 en cas d'échec.
"""
import json
import os
import re
import sys
import time
import traceback

RACINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, RACINE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk  # noqa: E402
from tkinter import filedialog, messagebox, simpledialog  # noqa: E402

PHASE, SORTIE = int(sys.argv[1]), sys.argv[2]
os.makedirs(SORTIE, exist_ok=True)
JOURNAL = os.path.join(SORTIE, f"resultats-phase{PHASE}.txt")

# --- fenêtres modales simulées ---------------------------------------------
REPONSES = {"askyesno": True, "askstring": "Incident AD"}
APPELS = []
messagebox.askyesno = lambda *a, **k: (APPELS.append(("askyesno", a[:2])), REPONSES["askyesno"])[1]
messagebox.showwarning = lambda *a, **k: APPELS.append(("showwarning", a[:2]))
messagebox.showerror = lambda *a, **k: APPELS.append(("showerror", a[:2]))
simpledialog.askstring = lambda *a, **k: REPONSES["askstring"]
filedialog.asksaveasfilename = lambda *a, **k: os.path.join(SORTIE, "rapport-scenario.html")
import webbrowser  # noqa: E402
webbrowser.open = lambda *a, **k: None

import anonymiseur  # noqa: E402

LOG = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "exemple-log-ad.txt"),
           encoding="utf-8").read() if os.path.exists(os.path.join(RACINE, "docs", "exemple-log-ad.txt")) else None
LOG = LOG or (
    "=== INC-2026-5120 - Compte de service compromis - Acme Industries ===\n"
    "2026-11-11 07:58:02 dc01.acme-industries.local Security 4625 Logon failure: ACME\\svc-backup from 10.20.40.17 (WS PC-0815)\n"
    "2026-11-11 07:59:31 dc01.acme-industries.local Directory 5136 Object modified: CN=Sophie Bernard,OU=Comptabilite,DC=acme-industries,DC=local\n"
    "2026-11-11 08:01:12 PC-0815 PowerShell 4104 Invoke-WebRequest -Uri https://deploy:Ghx7!q2Lm@repo.acme-industries.local/sync.ps1 -OutFile C:\\Users\\slefevre\\AppData\\Local\\Temp\\sync.ps1\n"
    "2026-11-11 08:02:40 sql01.acme-industries.local MSSQL Login succeeded for 'paie_app' Server=sql01;User Id=paie_app;Password=Paie#2026!;\n"
    "2026-11-11 08:05:44 srv-files02 smbd user slefevre copied /home/slefevre/exports/salaires_2026.csv\n"
    "2026-11-11 08:10:00 helpdesk Ticket opened by Marc Lefevre (+33 6 98 76 54 32), asset PC-0815\n"
    "--- doit rester en clair ---\n"
    "NT AUTHORITY\\SYSTEM, HKLM\\SYSTEM\\CurrentControlSet, java.lang.NullPointerException, report.pdf, S-1-5-18\n"
)
SENSIBLES = ["Acme Industries", "svc-backup", "10.20.40.17", "PC-0815", "Sophie Bernard", "Ghx7!q2Lm",
             "slefevre", "paie_app", "Paie#2026!", "Marc Lefevre", "+33 6 98 76 54 32", "dc01.acme-industries.local",
             "deploy", "INC-2026-5120"]
PIEGES = ["NT AUTHORITY\\SYSTEM", "HKLM\\SYSTEM\\CurrentControlSet", "java.lang.NullPointerException",
          "report.pdf", "S-1-5-18"]


class Echec(Exception):
    pass


def verifier(condition, message):
    if not condition:
        raise Echec(message)


def trouver_bouton(widget, textes):
    for enfant in widget.winfo_children():
        try:
            if enfant.winfo_class() in ("TButton", "Button") and enfant.cget("text") in textes:
                return enfant
        except tk.TclError:
            pass
        trouve = trouver_bouton(enfant, textes)
        if trouve:
            return trouve
    return None


def lancer():
    racine = tk.Tk()
    anonymiseur.activer_dpi()
    app = anonymiseur.Application(racine)
    resultats, contexte = [], {}

    def photo(nom):
        try:
            from PIL import ImageGrab
            racine.update()
            x, y, w, h = racine.winfo_rootx(), racine.winfo_rooty(), racine.winfo_width(), racine.winfo_height()
            ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(os.path.join(SORTIE, f"p{PHASE}-{nom}.png"))
        except Exception:
            pass

    def presse_papiers():
        return racine.clipboard_get()

    def coller(zone, texte):
        app.ecrire_presse_papiers(texte)
        app.coller(zone)  # comme le bouton « Coller »

    # ------------------------------------------------------------------ phase 1
    def accueil():
        verifier(app.options.premier_lancement, "premier lancement non détecté")
        fen = getattr(app, "fenetre_accueil", None)
        verifier(fen is not None and fen.winfo_exists(), "écran d'accueil absent")
        bouton = trouver_bouton(fen, ("Commencer", "Get started"))
        verifier(bouton is not None, "bouton Commencer introuvable")
        bouton.invoke()
        verifier(not fen.winfo_exists(), "l'écran d'accueil ne s'est pas fermé")
        verifier(os.path.exists(app.options.chemin), "options.json non créé après l'accueil")

    def langue_fr():
        app.options.langue = "fr"
        app.t = anonymiseur.Traducteur("fr")
        for c in app.conversations:
            c.moteur.langue = "fr"
        app.reconstruire()
        verifier(app.onglets.tab(0, "text").startswith("1. Anonymiser"), "interface pas en français")

    def reglages():
        app.options.permanents = ["Acme Industries"]
        app.options.motifs = [{"titre": "Postes", "motif": r"PC-\d{4}"}, {"titre": "Tickets", "motif": r"INC-\d{4}-\d+"}]
        app.sauver_options()

    def masquage_personnalise():
        avant = (list(app.options.permanents), dict(app.options.etiquettes), [dict(m) for m in app.options.motifs])
        app.ouvrir_options()
        fen = app.fenetre_options
        noms = [app.onglets_options.tab(i, "text") for i in range(len(app.onglets_options.tabs()))]
        verifier(noms == ["Général", "Détection", "Masquage personnalisé", "Consigne pour l'IA"], f"onglets : {noms}")
        app.onglets_options.select(2)
        champ_texte, champ_nom, est_regex, type_change, ajouter, arbre, elements = app.saisie_perso
        verifier(len(arbre.get_children()) == 3, f"termes et motifs existants : {len(arbre.get_children())}")
        champ_texte.insert(0, "Vallorie Logistique")
        champ_nom.insert(0, "client principal")
        ajouter()
        est_regex.set(True)
        type_change()
        champ_texte.insert(0, r"SRV-[A-Z]+\d*")
        champ_nom.insert(0, "Serveurs")
        ajouter()
        est_regex.set(True)
        champ_texte.insert(0, "SRV-(")
        ajouter()  # expression invalide : refusée
        valeurs = [arbre.item(i, "values") for i in arbre.get_children()]
        verifier(len(valeurs) == 5, f"lignes : {valeurs}")
        verifier(("Vallorie Logistique", "Texte exact", "[CLIENT_PRINCIPAL]") in valeurs, f"terme : {valeurs}")
        verifier((r"SRV-[A-Z]+\d*", "Expression régulière", "Serveurs") in valeurs, f"motif : {valeurs}")
        app.root.update()
        photo_fenetre = fen
        try:
            from PIL import ImageGrab
            x, y = photo_fenetre.winfo_rootx(), photo_fenetre.winfo_rooty()
            ImageGrab.grab(bbox=(x, y, x + photo_fenetre.winfo_width(), y + photo_fenetre.winfo_height())).save(
                os.path.join(SORTIE, "p1-0-options-perso.png"))
        except Exception:
            pass
        trouver_bouton(fen, ("Enregistrer", "Save")).invoke()
        racine.update()
        o = app.options
        verifier("Vallorie Logistique" in o.permanents and o.etiquettes.get("Vallorie Logistique") == "CLIENT_PRINCIPAL",
                 f"terme mal enregistré : {o.permanents} {o.etiquettes}")
        verifier({"titre": "Serveurs", "motif": r"SRV-[A-Z]+\d*"} in o.motifs and len(o.motifs) == 3,
                 f"motifs : {o.motifs}")
        o.permanents, o.etiquettes, o.motifs = avant
        app.sauver_options()

    def renommer():
        app.renommer_conversation()
        verifier(app.conv.nom == "Incident AD", f"renommage : {app.conv.nom!r}")

    def termes_conversation():
        for terme in ("Sophie Bernard", "Marc Lefèvre"):
            app.termes.champ.insert(0, terme)
            app.ajouter_terme()
        verifier(app.conv.termes == ["Marc Lefèvre", "Sophie Bernard"], f"termes : {app.conv.termes}")

    def jeton_terme_conversation():
        # Jeton parlant pour un terme de la conversation : sélection, modification, mise à jour
        i = app.conv.termes.index("Sophie Bernard")
        app.termes.arbre.selection_set(f"t{i}")
        racine.update()
        verifier(app.termes.champ.get() == "Sophie Bernard", "terme non chargé dans le champ")
        verifier(app.termes.bouton.cget("text") in ("Mettre à jour", "Update"), "bouton « Mettre à jour » absent")
        app.termes.champ_jeton.insert(0, "victime")
        app.ajouter_terme()
        racine.update()
        verifier(app.conv.etiquettes == {"Sophie Bernard": "VICTIME"}, f"jeton : {app.conv.etiquettes}")
        verifier(app.conv.termes == ["Marc Lefèvre", "Sophie Bernard"], f"termes : {app.conv.termes}")
        valeurs = [tuple(app.termes.arbre.item(x, "values")) for x in app.termes.arbre.get_children()]
        verifier(("Sophie Bernard", "[VICTIME]", "✕") in valeurs, f"liste : {valeurs}")
        verifier(app.titre_termes.cget("text").startswith("Masquage personnalisé de cette conversation"),
                 f"titre : {app.titre_termes.cget('text')}")
        # Jeton déjà pris par un terme permanent : refusé
        app.termes.arbre.selection_set(f"t{app.conv.termes.index('Marc Lefèvre')}")
        racine.update()
        app.options.etiquettes = {"Acme Industries": "ENTREPRISE"}
        app.termes.champ_jeton.insert(0, "ENTREPRISE")
        app.ajouter_terme()
        verifier("Marc Lefèvre" not in app.conv.etiquettes, "jeton déjà pris accepté")
        app.options.etiquettes = {}
        app.termes.vider()
        # Croix de la 3e colonne : supprime la ligne (sans la charger dans les champs)
        app.termes.champ.insert(0, "Terme temporaire")
        app.ajouter_terme()
        racine.update()
        iid = f"t{app.conv.termes.index('Terme temporaire')}"
        app.onglets.select(2)  # la croix n'a de position que si l'onglet est affiché
        racine.update()
        app.termes.arbre.see(iid)
        racine.update()
        x, y, w, h = app.termes.arbre.bbox(iid, "suppr")
        retour = app.termes.clic(type("E", (), {"x": x + w // 2, "y": y + h // 2})())
        verifier(retour == "break" and "Terme temporaire" not in app.conv.termes, f"croix : {app.conv.termes}")
        verifier(app.termes.champ.get() == "", "la croix a chargé la ligne dans les champs")
        verifier(not trouver_bouton(app.root, ("Toujours masquer", "Supprimer")), "boutons encore présents")
        photo("0b-jeton-conversation")
        app.onglets.select(0)

    def coller_log():
        coller(app.source, LOG)

    def verifier_anonymisation():
        sortie = app.sortie.lire()
        fuites = [v for v in SENSIBLES if v in sortie]
        verifier(not fuites, f"valeurs en clair dans le texte pour l'IA : {fuites}")
        abimes = [p for p in PIEGES if p not in sortie]
        verifier(not abimes, f"pièges masqués : {abimes}")
        verifier("[ENTREPRISE]" not in sortie and "[NOM_1]" in sortie, "jeton automatique attendu pour l'entreprise")
        verifier("[VICTIME]" in sortie and "Sophie Bernard" not in sortie, "jeton de conversation non appliqué")
        contexte["nb_elements"] = len(app.moteur.jetons())
        verifier(contexte["nb_elements"] >= 15, f"trop peu d'éléments : {contexte['nb_elements']}")
        verifier(app.onglets.tab(2, "text").endswith(f"({contexte['nb_elements']})"), "compteur de l'onglet 3")
        photo("1-anonymise")

    def recherche():
        app.source.texte.event_generate("<Control-f>")
        racine.update()
        verifier(app.recherche_ouverte(), "Ctrl+F n'ouvre pas la recherche")
        app.champ_recherche.insert(0, "ACME")
        app.chercher()
        attendu = len(re.findall("acme", app.source.lire(), re.IGNORECASE))
        verifier(len(app.resultats_recherche) == attendu and attendu > 5, f"résultats : {len(app.resultats_recherche)}/{attendu}")
        verifier(app.compte_recherche.cget("text") == f"1 / {attendu}", f"compteur : {app.compte_recherche.cget('text')}")
        app.champ_recherche.event_generate("<Return>")
        app.champ_recherche.event_generate("<Return>")
        racine.update()
        verifier(app.position_recherche == 2, "Entrée ne passe pas au suivant")
        app.aller_recherche(-3)
        verifier(app.position_recherche == attendu - 1, "précédent depuis le premier : retour au dernier")
        photo("1c-recherche")
        app.champ_recherche.delete(0, "end")
        app.champ_recherche.insert(0, "introuvable-xyz")
        app.chercher()
        verifier(app.compte_recherche.cget("text") in ("Aucun résultat", "No results"), "message sans résultat")
        app.champ_recherche.event_generate("<Escape>")
        racine.update()
        verifier(not app.recherche_ouverte() and not app.source.texte.tag_ranges("recherche"), "Échap ne ferme pas")

    def tri_elements():
        app.onglets.select(2)
        racine.update()
        arbre = app.arbre
        valeurs = lambda col: [arbre.set(i, col) for i in arbre.get_children()]
        depart = list(arbre.get_children())
        cle = lambda x: anonymiseur.cle_tri("valeur", x)
        arbre.event_generate("<Button-1>")  # clic neutre
        app.trier_elements("valeur")
        racine.update()
        v = valeurs("valeur")
        verifier([cle(x) for x in v] == sorted(cle(x) for x in v), f"tri croissant : {v[:6]}")
        verifier(cle("élodie") < cle("Etienne") < cle("zoé"), "accents et majuscules ignorés")
        verifier(arbre.heading("valeur", "text").endswith("▲"), "flèche ▲ absente")
        photo("1d-tri")
        app.trier_elements("valeur")
        racine.update()
        verifier([cle(x) for x in valeurs("valeur")] == sorted((cle(x) for x in v), reverse=True), "tri décroissant")
        verifier(arbre.heading("valeur", "text").endswith("▼"), "flèche ▼ absente")
        app.trier_elements("valeur")
        racine.update()
        verifier(list(arbre.get_children()) == depart, "retour à l'ordre d'apparition")
        verifier(not arbre.heading("valeur", "text").endswith(("▲", "▼")), "flèche restée")
        app.trier_elements("jeton")
        racine.update()
        jetons = valeurs("jeton")
        ip = [j for j in jetons if j.startswith("[IP_privée_")]
        verifier(ip == sorted(ip, key=lambda j: int(re.search(r"(\d+)\]$", j).group(1))),
                 f"ordre naturel des jetons : {ip}")
        app.trier_elements("nb")
        racine.update()
        nb = [int(x) if x.isdigit() else 0 for x in valeurs("nb")]
        verifier(nb == sorted(nb, reverse=True), f"« Ici » : plus fréquents d'abord : {nb}")
        verifier(arbre.heading("nb", "text").endswith("▼"), "flèche ▼ attendue sur « Ici »")
        app.trier_elements("type")  # laissé trié par type : la relance doit s'en souvenir
        racine.update()
        app.onglets.select(0)

    def copier_pour_ia():
        app.bouton_copier_ia.invoke()
        envoye = presse_papiers()
        verifier(envoye.startswith("Consigne"), "consigne absente du presse-papiers")
        fuites = [v for v in SENSIBLES if v in envoye]
        verifier(not fuites, f"fuite dans le presse-papiers : {fuites}")
        verifier(len(app.conv.envois) == 1, f"envois enregistrés : {len(app.conv.envois)}")
        contexte["envoi1"] = envoye

    def jeton_de(valeur):
        return next(j for j in app.moteur.jetons() if app.moteur.info(j)[1] == valeur)

    def reponse_ia():
        compte, ip, ticket = jeton_de("ACME\\svc-backup"), jeton_de("10.20.40.17"), jeton_de("INC-2026-5120")
        for j in (compte, ip, ticket, jeton_de("slefevre")):
            verifier(j in contexte["envoi1"], f"{j} absent de l'envoi")
        # Réponse d'IA réaliste : jetons repris, dont certains déformés (minuscules, Markdown échappé)
        reponse = ("## Analyse\n\n" + f"Le compte {compte} a été utilisé depuis {ip.lower()}.\n"
                   + f"- Chemin : `C:\\Users\\{jeton_de('slefevre')}\\AppData`\n"
                   + f"- Ticket {ticket.replace('_', chr(92) + '_')}\n"
                   + "Inconnu : [IP_99]\n")
        contexte["reponse"] = reponse
        coller(app.reponse, reponse)

    def verifier_restauration():
        restauree = app.restauree.lire()
        verifier("Le compte ACME\\svc-backup a été utilisé depuis 10.20.40.17." in restauree, f"restauration : {restauree!r}")
        verifier("[IP_99]" in restauree, "le jeton inconnu devrait rester tel quel")
        verifier("C:\\Users\\slefevre\\AppData" in restauree, f"chemin mal restauré : {restauree!r}")
        verifier("INC-2026-5120" in restauree, "jeton échappé en Markdown non restauré")
        verifier(len(app.resultat_reponse.inconnus) == 1, "un seul jeton inconnu attendu")
        app.bouton_copier.invoke()
        verifier(presse_papiers() == restauree, "le bouton Copier ne copie pas la réponse restaurée")
        app.onglets.select(1)
        photo("2-restaure")

    def survol():
        app.onglets.select(0)
        racine.update()
        def bulle_sur(zone, valeur):
            zone.texte.see("1.0")
            racine.update()
            debut = zone.texte.search(valeur, "1.0", "end")
            verifier(debut, f"{valeur} introuvable dans la zone")
            x, y, w, h = zone.texte.bbox(f"{debut}+2c")
            element = zone._element_sous(x + 1, y + h // 2)
            verifier(element, f"rien sous le pointeur pour {valeur}")
            zone._survoler(type("E", (), {"x": x + 1, "y": y + h // 2, "x_root": 50, "y_root": 50})())
            verifier(zone._bulle, "bulle non affichée")
            texte = zone._bulle[1]
            zone._cacher_bulle()
            return texte
        ip = jeton_de("10.20.40.17")
        verifier(bulle_sur(app.source, "10.20.40.17").startswith(ip), "survol côté original : jeton attendu")
        verifier(bulle_sur(app.sortie, ip).startswith("10.20.40.17"), "survol côté IA : valeur attendue")
        # Ligne survolée : en surbrillance des deux côtés
        app.source.texte.see("1.0")
        racine.update()
        x, y, w, h = app.source.texte.bbox("3.5")
        app.source._survoler(type("E", (), {"x": x, "y": y + h // 2, "x_root": 50, "y_root": 50})())
        app.source._cacher_bulle()
        for zone in (app.source, app.sortie):
            plage = [str(i) for i in zone.texte.tag_ranges("ligne")]
            verifier(plage == ["3.0", "4.0"], f"surbrillance de ligne : {plage}")
        photo("1b-ligne-survolee")
        app.source._quitter()
        verifier(not app.sortie.texte.tag_ranges("ligne"), "surbrillance non retirée en quittant la zone")
        app.onglets.select(1)
        racine.update()
        verifier(bulle_sur(app.restauree, "10.20.40.17").startswith(ip), "survol réponse restaurée")
        verifier(bulle_sur(app.reponse, "[IP_99]") == app.t("bulle_inconnu"), "survol jeton inconnu")

    def ne_pas_masquer():
        jeton_ip = next(j for j in app.moteur.jetons() if j.startswith("[IP_"))
        valeur = app.moteur.info(jeton_ip)[1]
        app.basculer_element(jeton_ip)
        verifier(valeur in app.sortie.lire(), "l'IP laissée en clair n'apparaît pas")
        app.basculer_element(jeton_ip)
        verifier(valeur not in app.sortie.lire(), "l'IP masquée à nouveau apparaît encore")

    def jeton_personnalise():
        app.options.etiquettes = {"Acme Industries": "ENTREPRISE"}
        app.sauver_options()
        coller(app.source, "Suite : Acme Industries confirme. ACME\\svc-backup bloqué sur PC-0815.")

    def verifier_annonce():
        verifier("[ENTREPRISE]" in app.sortie.lire(), "jeton personnalisé non appliqué")
        verifier("[COMPTE_1]" in app.sortie.lire(), "jeton du compte non conservé d'un message à l'autre")
        app.bouton_copier_ia.invoke()
        envoye = presse_papiers()
        verifier("[NOM_1] s'appelle désormais [ENTREPRISE]" in envoye, f"annonce absente : {envoye[:300]!r}")
        coller(app.source, "Et Acme Industries encore.")

    def verifier_annonce_unique():
        app.bouton_copier_ia.invoke()
        verifier("désormais" not in presse_papiers(), "annonce répétée")
        verifier(app.moteur.restaurer("[NOM_1] = [ENTREPRISE]").texte == "Acme Industries = Acme Industries",
                 "ancien et nouveau jeton doivent être restaurés")

    def rapport():
        REPONSES["askyesno"] = False  # ne pas ouvrir le navigateur
        app.exporter_rapport()
        REPONSES["askyesno"] = True
        chemin = os.path.join(SORTIE, "rapport-scenario.html")
        verifier(os.path.exists(chemin), "rapport non créé")
        page = open(chemin, encoding="utf-8").read()
        import html as h
        texte = h.unescape(page)
        verifier("Envoi 3," in texte and "Envoi 4," not in texte, "nombre d'envois dans le rapport")
        verifier("Paie#2026!" in texte and "C:\\Users" in texte, "valeurs d'origine absentes du rapport")
        verifier(re.search(r"envoyés en clair par erreur</th><td>0<", texte), "fuite signalée à tort")
        verifier(os.environ.get("USERNAME", "") in texte, "compte Windows absent du sous-titre")

    def conversations():
        premiere = app.conv
        app.nouvelle_conversation()
        verifier(app.conv is not premiere and app.conversations[0] is app.conv, "nouvelle conversation pas en haut")
        REPONSES["askstring"] = "Panne imprimante"
        app.renommer_conversation()
        coller(app.source, "L'imprimante 10.0.5.20 de Marc Lefèvre ne répond plus.")
        contexte["premiere"] = premiere

    def epingler():
        verifier("[IP_privée_1]" in app.sortie.lire(), "chaque conversation doit avoir ses propres jetons")
        app.arbre_conv.selection_set(contexte["premiere"].id)
        app.changer_conversation()
        verifier(app.conv is contexte["premiere"], "changement de conversation")
        app.basculer_epingle()
        lignes = app.arbre_conv.get_children()
        verifier(app.arbre_conv.item(lignes[0], "text") in ("Épinglées", "Pinned"), "rubrique Épinglées absente")
        verifier(lignes[1] == contexte["premiere"].id, "la conversation épinglée n'est pas en tête")
        photo("3-epingle")

    def restaurer_ancienne_reponse():
        coller(app.reponse, contexte["reponse"])

    def verifier_ancienne_reponse():
        verifier("slefevre" in app.restauree.lire(), "réponse du premier échange plus restaurée")

    def anglais_et_sombre():
        app.options.langue, app.options.theme = "en", "sombre"
        app.t = anonymiseur.Traducteur("en")
        for c in app.conversations:
            c.moteur.langue = "en"
        app.reconstruire()
        app.appliquer_theme()
        verifier(app.onglets.tab(0, "text").startswith("1. Anonymize"), "interface pas en anglais")
        verifier(app.theme_applique == "sombre", "thème sombre non appliqué")
        app.sauver_options()

    def anglais_jetons():
        coller(app.source, "New contact: jane.doe@example.org from Acme Industries.")

    def verifier_anglais():
        sortie = app.sortie.lire()
        verifier("[EMAIL_" in sortie and "[ENTREPRISE]" in sortie, f"anglais : {sortie!r}")
        verifier("slefevre" in app.moteur.restaurer(contexte["reponse"]).texte, "anciens jetons français perdus")
        photo("4-anglais-sombre")

    def fermer_conversation():
        nb = len(app.conversations)
        app.arbre_conv.selection_set(app.conversations[0].id if app.conversations[0] is not contexte["premiere"]
                                     else app.conversations[1].id)
        app.changer_conversation()
        app.fermer_conversation()
        verifier(len(app.conversations) == nb - 1, "conversation non fermée")
        verifier(app.conv is contexte["premiere"], "mauvaise conversation après fermeture")

    def gros_log():
        lignes = [f"2026-11-12 08:{i % 60:02d}:01 srv{i % 40}.acme.local [10.0.{i % 250}.{i % 200}] GET /api/v1/x?id={i} "
                  f"user{i % 50}@acme.fr ACME\\u{i % 30}" for i in range(3000)]
        app.nouvelle_conversation()
        debut = time.perf_counter()
        app.source.ecrire("\n".join(lignes))
        app.actualiser()
        racine.update()
        duree = time.perf_counter() - debut
        contexte["duree"] = duree
        contexte["elements_gros_log"] = len(app.moteur.jetons())
        verifier(duree < 5, f"gros log trop lent : {duree:.2f} s")
        verifier("10.0." not in app.sortie.lire(), "IP en clair dans le gros log")

    def defilement_jumele():
        app.onglets.select(0)
        racine.update()
        source, sortie = app.source.texte, app.sortie.texte
        ligne = lambda t: int(t.index("@0,0").split(".")[0])
        app.source.prendre_main()
        source.yview("1500.0")
        racine.update()
        verifier(ligne(sortie) == ligne(source) == 1500, f"droite pas alignée : {ligne(source)} / {ligne(sortie)}")
        app.sortie.prendre_main()
        sortie.yview_scroll(40, "units")
        racine.update()
        verifier(ligne(source) == ligne(sortie) > 1500, f"gauche pas alignée : {ligne(source)} / {ligne(sortie)}")
        sortie.yview_moveto(1.0)
        for _ in range(10):  # le défilement de l'autre zone suit au rafraîchissement suivant
            racine.update()
            if source.yview()[1] >= 1.0:
                break
            time.sleep(0.05)
        verifier(source.yview()[1] >= 1.0, "la gauche n'est pas allée en bas")
        photo("3b-defilement")

    def colonne_reduite():
        racine.update()
        largeur = app.colonne.winfo_width()
        verifier(str(app.lateral.winfo_class()) == "TFrame", "la colonne ne doit plus être redimensionnable")
        app.basculer_colonne()
        racine.update()
        verifier(app.colonne_mini.winfo_ismapped() and not app.colonne_pleine.winfo_ismapped(), "colonne non réduite")
        verifier(app.colonne.winfo_width() < largeur / 2, f"largeur réduite : {app.colonne.winfo_width()} / {largeur}")
        lignes = [i for i in app.arbre_mini.get_children() if not i.startswith("sep-")]
        verifier(len(lignes) == len(app.conversations), f"conversations dans la colonne réduite : {len(lignes)}")
        verifier(app.arbre_mini.selection() == (app.conv.id,), "conversation courante non sélectionnée")
        verifier(app.arbre_mini.item(contexte["premiere"].id, "values")[0] == "IA", "initiales de « Incident AD »")
        autre = next(i for i in lignes if i != app.conv.id)
        depart = app.conv.id
        app.arbre_mini.selection_set(autre)
        racine.update()
        verifier(app.conv.id == autre, "choisir une conversation dans la colonne réduite")
        app.arbre_mini.selection_set(depart)
        racine.update()
        verifier(app.conv.id == depart, "retour à la conversation de départ")
        photo("3c-colonne-reduite")
        app.basculer_colonne()
        racine.update()
        verifier(abs(app.colonne.winfo_width() - largeur) <= 2, "largeur non retrouvée en dépliant")
        app.basculer_colonne()  # laissée réduite : la relance doit s'en souvenir
        racine.update()

    def quitter_phase1():
        app.arbre_conv.selection_set(contexte["premiere"].id)
        app.changer_conversation()
        etat = {"premiere_id": contexte["premiere"].id, "reponse": contexte["reponse"],
                "nb_conversations": len(app.conversations), "nb_elements": len(contexte["premiere"].moteur.valide)}
        with open(os.path.join(SORTIE, "etat-phase1.json"), "w", encoding="utf-8") as f:
            json.dump(etat, f)
        app.quitter()

    # ------------------------------------------------------------------ phase 2
    def relance():
        etat = json.load(open(os.path.join(SORTIE, "etat-phase1.json"), encoding="utf-8"))
        contexte.update(etat)
        verifier(not app.options.premier_lancement, "l'écran d'accueil ne doit pas revenir")
        verifier(not getattr(app, "fenetre_accueil", None), "écran d'accueil affiché à la relance")
        verifier(len(app.conversations) == etat["nb_conversations"], "nombre de conversations")
        verifier(app.conv.id == etat["premiere_id"], "conversation courante non restaurée")
        verifier(app.conv.epingle, "épinglage perdu")
        verifier(app.conv.nom == "Incident AD", "nom perdu")
        verifier(app.conv.etiquettes == {"Sophie Bernard": "VICTIME"}, f"jeton de conversation perdu : {app.conv.etiquettes}")
        verifier(len(app.conv.moteur.valide) == etat["nb_elements"], "jetons perdus")
        verifier(app.options.etiquettes == {"Acme Industries": "ENTREPRISE"}, "jeton personnalisé perdu")
        verifier(app.options.langue == "en" and app.theme_applique == "sombre", "langue ou thème perdus")
        verifier(len(app.options.motifs) == 2 and app.options.motifs[0]["titre"] == "Postes", "motifs perdus")
        verifier(len(app.conv.envois) == 3, f"envois perdus : {len(app.conv.envois)}")
        verifier(app.options.tri_elements == ["type", False], f"tri non conservé : {app.options.tri_elements}")
        racine.update()
        verifier(app.options.colonne_reduite and app.colonne_mini.winfo_ismapped(), "colonne réduite non conservée")
        verifier(app.colonne.winfo_width() < 120 * app.echelle, f"colonne réduite trop large : {app.colonne.winfo_width()}")
        app.basculer_colonne()
        racine.update()
        verifier(app.colonne_pleine.winfo_ismapped(), "colonne non dépliée à la relance")

    def relance_restauration():
        coller(app.reponse, contexte["reponse"])

    def verifier_relance_restauration():
        verifier("C:\\Users\\slefevre\\AppData" in app.restauree.lire(), "restauration après relance")
        brut = open(os.path.join(os.environ["APPDATA"], "IA-Anonymiser", "conversations.dat"), "rb").read()
        verifier(brut.startswith(b"IAA1"), "fichier des conversations non chiffré par DPAPI")
        verifier(b"slefevre" not in brut and b"Paie#2026" not in brut, "valeurs lisibles dans le fichier chiffré")
        photo("5-relance")

    def fin():
        app.quitter()

    etapes = {
        1: [accueil, langue_fr, reglages, masquage_personnalise, renommer, termes_conversation, jeton_terme_conversation, coller_log, verifier_anonymisation, recherche, tri_elements,
            copier_pour_ia, reponse_ia, verifier_restauration, survol, ne_pas_masquer, jeton_personnalise, verifier_annonce,
            verifier_annonce_unique, rapport, conversations, epingler, restaurer_ancienne_reponse,
            verifier_ancienne_reponse, anglais_et_sombre, anglais_jetons, verifier_anglais, fermer_conversation,
            gros_log, defilement_jumele, colonne_reduite, quitter_phase1],
        2: [relance, relance_restauration, verifier_relance_restauration, fin],
    }[PHASE]

    def suivante(i=0):
        if i >= len(etapes):
            return
        etape = etapes[i]
        try:
            etape()
            resultats.append(("OK", etape.__name__, ""))
        except Echec as e:
            resultats.append(("ÉCHEC", etape.__name__, str(e)))
        except Exception:
            resultats.append(("ERREUR", etape.__name__, traceback.format_exc(limit=3)))
        if etape.__name__ in ("quitter_phase1", "fin"):
            return
        racine.after(700, suivante, i + 1)  # laisse passer le délai de recalcul (250 ms) et l'affichage

    racine.after(1200, suivante)
    racine.after(180000, racine.destroy)  # garde-fou
    racine.mainloop()

    with open(JOURNAL, "w", encoding="utf-8") as f:
        for statut, nom, detail in resultats:
            f.write(f"{statut:6} {nom}{(' : ' + detail) if detail else ''}\n")
        if "duree" in contexte:
            f.write(f"\ngros log (3 000 lignes) : {contexte['duree']:.2f} s\n")
        f.write(f"fenêtres simulées : {APPELS}\n")
    attendu = len(etapes)
    ok = sum(1 for r in resultats if r[0] == "OK")
    print(open(JOURNAL, encoding="utf-8").read())
    print(f"{ok}/{attendu} étapes réussies")
    sys.exit(0 if ok == attendu else 1)


if __name__ == "__main__":
    lancer()
