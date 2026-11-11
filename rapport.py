"""Rapport de preuve d'une conversation, au format HTML.

Il ne contient AUCUNE valeur d'origine : seulement les jetons, leurs types, et le texte exact de chaque
envoi à l'IA (déjà anonymisé), avec sa date et son empreinte SHA-256.
"""
import datetime
import hashlib
import html

from moteur import TYPES_AUTO

STYLE = """
body { font-family: "Segoe UI", system-ui, sans-serif; color: #1b1b1b; max-width: 960px; margin: 32px auto;
       padding: 0 24px; line-height: 1.5; }
h1 { font-size: 22px; margin-bottom: 4px; }
h2 { font-size: 16px; margin-top: 32px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
.meta { color: #5f6368; margin-top: 0; }
.garantie { background: #eef6ee; border-left: 4px solid #2e7d32; padding: 10px 14px; margin: 16px 0; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }
th { background: #f5f5f7; }
td.n { text-align: right; }
.clair { color: #8a8a8a; }
code, pre { font-family: Consolas, "Cascadia Mono", monospace; font-size: 13px; }
pre { background: #f7f7f8; border: 1px solid #e5e5e5; padding: 12px; white-space: pre-wrap;
      word-break: break-word; }
.empreinte { color: #5f6368; font-size: 12px; word-break: break-all; }
@media print { body { margin: 0; } pre { page-break-inside: avoid; } }
"""


def _date(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def empreinte(texte):
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()


def generer(conversation, options, t, version, libelle_type, maintenant=None):
    """conversation : objet Conversation ; options : Options ; t : Traducteur ; libelle_type(type, valeur)."""
    e = html.escape
    maintenant = maintenant or datetime.datetime.now().timestamp()
    moteur = conversation.moteur
    jetons = list(moteur.valide)  # seuls les jetons réellement envoyés (validés) sont rapportés
    exclus = [j for j in jetons if j in moteur.exclus]

    par_type = {}
    for j in jetons:
        if j not in moteur.exclus:
            type_, valeur = moteur.valide[j]
            cle = libelle_type(type_, valeur)
            par_type[cle] = par_type.get(cle, 0) + 1

    lignes = [
        "<!DOCTYPE html>",
        f'<html lang="{t.langue}"><head><meta charset="utf-8">',
        f"<title>{e(t('rp_titre', c=conversation.nom))}</title><style>{STYLE}</style></head><body>",
        f"<h1>{e(t('rp_titre', c=conversation.nom))}</h1>",
        f"<p class=\"meta\">{e(t('rp_genere', d=_date(maintenant), v=version))}</p>",
        f"<div class=\"garantie\">{e(t('rp_garantie'))}</div>",

        f"<h2>{e(t('rp_conversation'))}</h2><table>",
        f"<tr><th>{e(t('rp_nom'))}</th><td>{e(conversation.nom)}</td></tr>",
        f"<tr><th>{e(t('rp_creee'))}</th><td>{e(_date(conversation.cree) if conversation.cree else t('rp_inconnue'))}</td></tr>",
        f"<tr><th>{e(t('rp_activite'))}</th><td>{e(_date(conversation.activite))}</td></tr>",
        f"<tr><th>{e(t('rp_nb_envois'))}</th><td>{len(conversation.envois)}</td></tr>",
        "</table>",

        f"<h2>{e(t('rp_reglages'))}</h2><table>",
        f"<tr><th>{e(t('rp_types'))}</th><td>"
        + e(", ".join(t(f"type_{x}") for x in TYPES_AUTO if x in options.types) or "—") + "</td></tr>",
        f"<tr><th>{e(t('rp_permanents'))}</th><td>{len(options.permanents)}</td></tr>",
        f"<tr><th>{e(t('rp_conv_termes'))}</th><td>{len(conversation.termes)}</td></tr>",
        f"<tr><th>{e(t('rp_motifs'))}</th><td>{len(options.motifs)}</td></tr>",
        f"<tr><th>{e(t('rp_consigne'))}</th><td>{e(t('rp_oui') if options.consigne else t('rp_non'))}</td></tr>",
        "</table>",

        f"<h2>{e(t('rp_resume'))}</h2><table>",
        f"<tr><th>{e(t('col_type'))}</th><th class=\"n\">{e(t('rp_nombre'))}</th></tr>",
    ]
    for cle in sorted(par_type):
        lignes.append(f"<tr><td>{e(cle)}</td><td class=\"n\">{par_type[cle]}</td></tr>")
    lignes += [
        f"<tr><th>{e(t('rp_total_masques'))}</th><th class=\"n\">{len(jetons) - len(exclus)}</th></tr>",
        f"<tr><th>{e(t('rp_total_clair'))}</th><th class=\"n\">{len(exclus)}</th></tr>",
        "</table>",

        f"<h2>{e(t('rp_elements'))}</h2><table>",
        f"<tr><th>{e(t('col_jeton'))}</th><th>{e(t('col_type'))}</th><th>{e(t('rp_statut'))}</th></tr>",
    ]
    for j in jetons:
        type_, valeur = moteur.valide[j]
        clair = j in moteur.exclus
        statut = t("rp_statut_clair") if clair else t("rp_statut_masque")
        classe = ' class="clair"' if clair else ""
        lignes.append(f"<tr{classe}><td><code>{e(j)}</code></td><td>{e(libelle_type(type_, valeur))}</td>"
                      f"<td>{e(statut)}</td></tr>")
    if not jetons:
        lignes.append(f"<tr><td colspan=\"3\">{e(t('rp_aucun_element'))}</td></tr>")
    lignes.append("</table>")

    lignes.append(f"<h2>{e(t('rp_envois'))}</h2>")
    if not conversation.envois:
        lignes.append(f"<p>{e(t('rp_aucun_envoi'))}</p>")
    for i, envoi in enumerate(conversation.envois, 1):
        texte = envoi["texte"]
        lignes += [
            f"<h3>{e(t('rp_envoi', n=i, d=_date(envoi['date'])))}</h3>",
            f"<p class=\"empreinte\">SHA-256 : {empreinte(texte)} · {len(texte)} {e(t('rp_caracteres'))}</p>",
            f"<pre>{e(texte)}</pre>",
        ]
    lignes += [f"<p class=\"meta\">{e(t('rp_pied'))}</p>", "</body></html>"]
    return "\n".join(lignes)
