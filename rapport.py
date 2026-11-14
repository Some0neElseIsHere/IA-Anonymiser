"""Rapport de preuve d'une conversation, au format HTML.

Il contient les éléments masqués avec leurs valeurs d'origine, et le texte exact de chaque envoi à l'IA
(anonymisé), avec sa date et son empreinte SHA-256. C'est donc un document sensible.
"""
import datetime
import getpass
import hashlib
import html
import os
import re

from moteur import JETON_RE, TYPES_AUTO, Anonymiseur, _cle, jeton_canonique

STYLE = """
body { font-family: "Segoe UI", system-ui, sans-serif; color: #1b1b1b; max-width: 1000px; margin: 32px auto;
       padding: 0 24px; line-height: 1.5; }
h1 { font-size: 22px; margin-bottom: 4px; }
h2 { font-size: 16px; margin-top: 32px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
.meta { color: #5f6368; margin-top: 0; }
.avertissement { background: #fff4e5; border-left: 4px solid #e65100; padding: 10px 14px; margin: 16px 0; }
.synthese { display: flex; flex-wrap: wrap; gap: 12px; margin: 12px 0 4px; }
.carte { border: 1px solid #e5e5e5; border-radius: 8px; padding: 10px 14px; min-width: 120px; }
.carte .n { font-size: 24px; font-weight: 600; }
.carte .l { color: #5f6368; font-size: 13px; }
.carte.alerte-carte { border-color: #e57373; background: #fdecea; }
.carte.alerte-carte .n { color: #b71c1c; }
.types { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0; }
.puce { background: #eef3fb; border-radius: 12px; padding: 2px 10px; font-size: 13px; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }
th { background: #f5f5f7; }
table.triable th { cursor: pointer; user-select: none; white-space: nowrap; }
table.triable th:after { content: " ↕"; color: #b0b0b0; }
table.triable th.asc:after { content: " ▲"; color: #1b1b1b; }
table.triable th.desc:after { content: " ▼"; color: #1b1b1b; }
.filtre { width: 100%; box-sizing: border-box; padding: 7px 10px; margin: 8px 0; border: 1px solid #ccc;
          border-radius: 6px; font-size: 14px; }
.clair { color: #8a8a8a; }
.fuite td { background: #fdecea; }
.fuite .statut { color: #b71c1c; font-weight: 600; }
.alerte { color: #b71c1c; font-weight: 600; }
.note { color: #5f6368; font-size: 12px; }
code, pre { font-family: Consolas, "Cascadia Mono", monospace; font-size: 13px; }
td code { word-break: break-all; }
pre { background: #f7f7f8; border: 1px solid #e5e5e5; padding: 12px; white-space: pre-wrap; word-break: break-word;
      margin-top: 6px; }
pre .jeton { background: #d2f0dc; color: #0f5132; border-radius: 3px; }
pre .fuite-texte { background: #ffcdd2; color: #8b0000; font-weight: 600; outline: 1px solid #e57373; }
details { border: 1px solid #e5e5e5; border-radius: 8px; padding: 8px 12px; margin: 10px 0; }
details > summary { cursor: pointer; font-weight: 600; }
details.avec-fuite { border-color: #e57373; }
.empreinte { color: #5f6368; font-size: 12px; word-break: break-all; margin: 6px 0 0; }
.boutons { margin: 8px 0; }
.boutons button { font: inherit; font-size: 13px; padding: 4px 10px; margin-right: 6px; cursor: pointer; }
@media print {
  body { margin: 0; max-width: none; padding: 0; font-size: 12px; }
  .filtre, .boutons, table.triable th:after { display: none; }
  details { border: none; padding: 0; }
  details > summary { list-style: none; }
  pre { page-break-inside: auto; }
  tr, .carte { page-break-inside: avoid; }
  h2 { page-break-after: avoid; }
  .avertissement, .fuite td, pre .jeton, pre .fuite-texte, .carte.alerte-carte {
    -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""

# Tri et filtre du tableau, ouverture des textes avant impression : autonome, sans connexion
SCRIPT = """
(function () {
  var table = document.getElementById("elements"), filtre = document.getElementById("filtre");
  function cle(cellule) {
    var t = (cellule.getAttribute("data-tri") || cellule.textContent).trim();
    return /^-?\\d+$/.test(t) ? parseInt(t, 10) : t.normalize("NFD").replace(/[\\u0300-\\u036f]/g, "").toLowerCase();
  }
  if (table) {
    var titres = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(titres, function (th, i) {
      th.addEventListener("click", function () {
        var desc = th.classList.contains("asc");
        Array.prototype.forEach.call(titres, function (x) { x.classList.remove("asc", "desc"); });
        th.classList.add(desc ? "desc" : "asc");
        var lignes = Array.prototype.slice.call(table.tBodies[0].rows);
        lignes.sort(function (a, b) {
          var x = cle(a.cells[i]), y = cle(b.cells[i]);
          var r = (typeof x === "number" && typeof y === "number") ? x - y : String(x).localeCompare(String(y), undefined, {numeric: true});
          return desc ? -r : r;
        });
        lignes.forEach(function (l) { table.tBodies[0].appendChild(l); });
      });
    });
  }
  if (filtre && table) {
    filtre.addEventListener("input", function () {
      var q = filtre.value.normalize("NFD").replace(/[\\u0300-\\u036f]/g, "").toLowerCase();
      Array.prototype.forEach.call(table.tBodies[0].rows, function (l) {
        var t = l.textContent.normalize("NFD").replace(/[\\u0300-\\u036f]/g, "").toLowerCase();
        l.style.display = t.indexOf(q) >= 0 ? "" : "none";
      });
    });
  }
  function tous(ouvrir) {
    Array.prototype.forEach.call(document.querySelectorAll("details"), function (d) {
      if (ouvrir) { d.setAttribute("data-avant", d.open ? "1" : ""); d.open = true; }
      else if (d.hasAttribute("data-avant")) { d.open = !!d.getAttribute("data-avant"); }
    });
  }
  window.addEventListener("beforeprint", function () { tous(true); });
  window.addEventListener("afterprint", function () { tous(false); });
  var o = document.getElementById("tout-ouvrir"), f = document.getElementById("tout-fermer");
  if (o) o.addEventListener("click", function () { tous(true); });
  if (f) f.addEventListener("click", function () {
    Array.prototype.forEach.call(document.querySelectorAll("details"), function (d) { d.open = false; });
  });
})();
"""


def _date(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def utilisateur_windows():
    """Compte Windows qui génère le rapport : DOMAINE\\utilisateur."""
    try:
        nom = os.environ.get("USERNAME") or getpass.getuser()
    except Exception:
        nom = "?"
    domaine = os.environ.get("USERDOMAIN", "")
    return f"{domaine}\\{nom}" if domaine else nom


def empreinte(texte):
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()


def envois_en_clair(valeur, type_, envois):
    """Numéros des envois où la valeur d'origine apparaît en clair (même règles que la détection)."""
    return [i for i, envoi in enumerate(envois, 1)
            if Anonymiseur._occurrences_connues(envoi["texte"], [(valeur, type_)], None)]


def jetons_dans(texte, jetons):
    """(début, fin, jeton) des jetons d'un texte : forme habituelle [TYPE_n] (même réécrite par l'IA)
    et jetons personnalisés ([ENTREPRISE]), cherchés tels quels."""
    connus = set(jetons)
    trouves = [(m.start(), m.end(), jeton_canonique(m.group(1), m.group(2))) for m in JETON_RE.finditer(texte)]
    for j in connus:
        if not JETON_RE.fullmatch(j):
            pos = texte.find(j)
            while pos != -1:
                trouves.append((pos, pos + len(j), j))
                pos = texte.find(j, pos + len(j))
    return sorted(trouves)


def _texte_envoi(texte, fuites, jetons):
    """Texte d'un envoi en HTML : jetons en vert, valeurs parties en clair en rouge à leur place exacte."""
    e = html.escape
    marques = [(d + (texte[d] == "\\"), f, "jeton") for d, f, _ in jetons_dans(texte, jetons)]
    marques += [(d, f, "fuite-texte") for d, f, _, _ in Anonymiseur._occurrences_connues(texte, fuites, None)]
    marques.sort(key=lambda x: (x[0], x[2] != "fuite-texte"))
    sortie, pos = [], 0
    for d, f, classe in marques:
        if d < pos:
            continue
        sortie.append(e(texte[pos:d]))
        sortie.append(f'<span class="{classe}">{e(texte[d:f])}</span>')
        pos = f
    sortie.append(e(texte[pos:]))
    return "".join(sortie)


def contenu_utile(texte, consignes=()):
    """Texte réellement soumis à l'IA : sans la consigne en tête (ses exemples [NOM_1], [EMAIL_1] ne
    désignent rien) ni les lignes d'annonce de changement de jeton."""
    for consigne in consignes:
        if consigne and texte.startswith(consigne.rstrip()):
            texte = texte[len(consigne.rstrip()):]
            break
    return "\n".join(l for l in texte.split("\n")
                     if not re.match(r"(?:Changement de jeton|Token change) ?: ", l))


def presence(jetons, envois, consignes=()):
    """Pour chaque jeton : (premier envoi où il apparaît, nombre d'envois qui le contiennent)."""
    vus = {j: [] for j in jetons}
    for i, envoi in enumerate(envois, 1):
        presents = {j for _, _, j in jetons_dans(contenu_utile(envoi["texte"], consignes), jetons)}
        for j in presents & set(vus):
            vus[j].append(i)
    return {j: (n[0] if n else None, len(n)) for j, n in vus.items()}


def renommages(moteur, premiers):
    """Jetons remplacés par un autre (jeton personnalisé choisi en cours de conversation) :
    {ancien: (nouveau, envoi où le nouveau apparaît)}. Même valeur, même type : le plus ancien est remplacé."""
    groupes = {}
    for j, (type_, valeur) in moteur.valide.items():
        groupes.setdefault((type_ if type_ not in ("NOM", "PERSO") else "NOM", _cle(valeur, type_)), []).append(j)
    resultat = {}
    for jetons in groupes.values():
        if len(jetons) < 2:
            continue
        jetons.sort(key=lambda j: (premiers.get(j) or 10 ** 9))
        for ancien, nouveau in zip(jetons, jetons[1:]):
            resultat[ancien] = (nouveau, premiers.get(nouveau))
    return resultat


def generer(conversation, options, t, version, libelle_type, maintenant=None, utilisateur=None):
    """conversation : objet Conversation ; options : Options ; t : Traducteur ; libelle_type(type, valeur)."""
    e = html.escape
    maintenant = maintenant or datetime.datetime.now().timestamp()
    utilisateur = utilisateur or utilisateur_windows()
    moteur = conversation.moteur
    envois = conversation.envois
    jetons = list(moteur.valide)  # seuls les jetons réellement envoyés (validés) sont rapportés
    titre = e(t("rp_titre", c=conversation.nom))
    en_clair = {j: envois_en_clair(moteur.valide[j][1], moteur.valide[j][0], envois) for j in jetons}
    fuites = [j for j in jetons if en_clair[j] and j not in moteur.exclus]
    from textes import CONSIGNES
    consignes = [getattr(options, "consigne_texte", None)] + [c for c in CONSIGNES.values()]
    consignes = [c for c in consignes if c]
    presences = presence(jetons, envois, consignes)
    remplaces = renommages(moteur, {j: p[0] for j, p in presences.items()})
    etiquettes_conv = getattr(conversation, "etiquettes", {}) or {}
    publics = getattr(conversation, "domaines_publics", False)
    types_conv = getattr(conversation, "types", None)
    types_conv = options.types if types_conv is None else types_conv

    # Synthèse : chiffres clés, éléments par type
    par_type = {}
    for j in jetons:
        type_, valeur = moteur.valide[j]
        if j not in remplaces:  # un élément renommé n'est compté qu'une fois
            libelle = libelle_type(type_, valeur)
            par_type[libelle] = par_type.get(libelle, 0) + 1
    nb_elements = sum(par_type.values())
    cartes = [(nb_elements, t("rp_s_elements"), False), (len(envois), t("rp_s_envois"), False),
              (len(fuites), t("rp_s_fuites"), bool(fuites)),
              (sum(1 for j in jetons if j in moteur.exclus), t("rp_s_clair"), False)]

    lignes = [
        "<!DOCTYPE html>",
        f'<html lang="{t.langue}"><head><meta charset="utf-8">',
        f"<title>{titre}</title><style>{STYLE}</style></head><body>",
        f"<h1>{titre}</h1>",
        f"<p class=\"meta\">{e(t('rp_genere', d=_date(maintenant), u=utilisateur, v=version))}</p>",
        f"<div class=\"avertissement\">{e(t('rp_avertissement'))}</div>",

        f"<h2>{e(t('rp_synthese'))}</h2>",
        '<div class="synthese">' + "".join(
            f'<div class="carte{" alerte-carte" if alerte else ""}"><div class="n">{n}</div>'
            f'<div class="l">{e(l)}</div></div>' for n, l, alerte in cartes) + "</div>",
        '<div class="types">' + "".join(
            f'<span class="puce">{e(l)} : {n}</span>' for l, n in sorted(par_type.items(), key=lambda x: -x[1]))
        + "</div>",

        f"<h2>{e(t('rp_conversation'))}</h2><table>",
        f"<tr><th>{e(t('rp_nom'))}</th><td>{e(conversation.nom)}</td></tr>",
        f"<tr><th>{e(t('rp_creee'))}</th><td>"
        f"{e(_date(conversation.cree) if conversation.cree else t('rp_inconnue'))}</td></tr>",
        f"<tr><th>{e(t('rp_activite'))}</th><td>{e(_date(conversation.activite))}</td></tr>",
        f"<tr><th>{e(t('rp_nb_envois'))}</th><td>{len(envois)}</td></tr>",
        f"<tr><th>{e(t('rp_nb_fuites'))}</th><td" + (' class="alerte"' if fuites else "") + f">{len(fuites)}</td></tr>",
        f"<tr><th>{e(t('rp_conv_termes'))}</th><td>{len(conversation.termes)}</td></tr>",
        f"<tr><th>{e(t('rp_jetons_conv'))}</th><td>"
        + (e(", ".join(f"{x} → [{j}]" for x, j in sorted(etiquettes_conv.items()))) or "—") + "</td></tr>",
        f"<tr><th>{e(t('rp_domaines_publics'))}</th><td>{e(t('rp_oui') if publics else t('rp_non'))}</td></tr>",
        "</table>",

        f"<h2>{e(t('rp_reglages'))}</h2><table>",
        f"<tr><th>{e(t('rp_types'))}</th><td>"
        + e(", ".join(t(f"type_{x}") for x in TYPES_AUTO if x in types_conv) or "—") + "</td></tr>",
        f"<tr><th>{e(t('rp_permanents'))}</th><td>{len(options.permanents)}</td></tr>",
        f"<tr><th>{e(t('rp_motifs'))}</th><td>{len(options.motifs)}</td></tr>",
        f"<tr><th>{e(t('rp_consigne'))}</th><td>{e(t('rp_oui') if options.consigne else t('rp_non'))}</td></tr>",
        "</table>",

        f"<h2>{e(t('rp_elements'))}</h2>",
        f'<input id="filtre" class="filtre" type="search" placeholder="{e(t("rp_filtrer"))}">',
        '<table id="elements" class="triable"><thead><tr>'
        f"<th>{e(t('col_jeton'))}</th><th>{e(t('col_valeur'))}</th><th>{e(t('col_type'))}</th>"
        f"<th>{e(t('rp_premier_envoi'))}</th><th>{e(t('rp_nb_envois_col'))}</th>"
        f"<th>{e(t('rp_statut'))}</th></tr></thead><tbody>",
    ]
    for j in jetons:
        type_, valeur = moteur.valide[j]
        numeros = ", ".join(str(n) for n in en_clair[j])
        if j in moteur.exclus:
            statut, classe = t("rp_statut_clair"), ' class="clair"'
            if numeros:
                statut += " " + t("rp_envois_numeros", n=numeros)
        elif numeros:
            statut, classe = t("rp_statut_fuite", n=numeros), ' class="fuite"'
        else:
            statut, classe = t("rp_statut_masque"), ""
        if j in remplaces:
            nouveau, envoi = remplaces[j]
            statut += " · " + (t("rp_renomme", j=nouveau, n=envoi) if envoi else t("rp_renomme_sans", j=nouveau))
        premier, nombre = presences[j]
        lignes.append(f"<tr{classe}><td><code>{e(j)}</code></td><td><code>{e(valeur)}</code></td>"
                      f"<td>{e(libelle_type(type_, valeur))}</td>"
                      f"<td data-tri=\"{premier or 0}\">{premier or '—'}</td><td>{nombre}</td>"
                      f"<td class=\"statut\">{e(statut)}</td></tr>")
    if not jetons:
        lignes.append(f"<tr><td colspan=\"6\">{e(t('rp_aucun_element'))}</td></tr>")
    lignes += ["</tbody></table>", f"<p class=\"note\">{e(t('rp_note_tableau'))}</p>"]

    lignes.append(f"<h2>{e(t('rp_envois'))}</h2>")
    if not envois:
        lignes.append(f"<p>{e(t('rp_aucun_envoi'))}</p>")
    else:
        lignes.append(f'<div class="boutons"><button id="tout-ouvrir" type="button">{e(t("rp_tout_ouvrir"))}</button>'
                      f'<button id="tout-fermer" type="button">{e(t("rp_tout_fermer"))}</button></div>')
    valeurs_fuites = [(moteur.valide[j][1], moteur.valide[j][0]) for j in fuites]
    for i, envoi in enumerate(envois, 1):
        texte = envoi["texte"]
        fuites_ici = [j for j in fuites if i in en_clair[j]]
        resume = t("rp_envoi", n=i, d=_date(envoi["date"]))
        resume += " · " + t("rp_envoi_jetons", n=len(jetons_dans(contenu_utile(texte, consignes), jetons)))
        if fuites_ici:
            resume += " · " + t("rp_envoi_fuites", n=len(fuites_ici))
        lignes += [
            f'<details{" class=\"avec-fuite\" open" if fuites_ici else ""}>'
            f"<summary>{e(resume)}</summary>",
            f"<p class=\"empreinte\">SHA-256 : {empreinte(texte)} · {len(texte)} {e(t('rp_caracteres'))}</p>",
            f"<pre>{_texte_envoi(texte, valeurs_fuites, jetons)}</pre>",
            "</details>",
        ]
    lignes += [f"<p class=\"meta\">{e(t('rp_pied'))}</p>", f"<script>{SCRIPT}</script>", "</body></html>"]
    return "\n".join(lignes)
