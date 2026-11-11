"""Rapport de preuve d'une conversation, au format HTML.

Il contient les éléments masqués avec leurs valeurs d'origine, et le texte exact de chaque envoi à l'IA
(anonymisé), avec sa date et son empreinte SHA-256. C'est donc un document sensible.
"""
import datetime
import getpass
import hashlib
import html
import os

from moteur import TYPES_AUTO

STYLE = """
body { font-family: "Segoe UI", system-ui, sans-serif; color: #1b1b1b; max-width: 960px; margin: 32px auto;
       padding: 0 24px; line-height: 1.5; }
h1 { font-size: 22px; margin-bottom: 4px; }
h2 { font-size: 16px; margin-top: 32px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
.meta { color: #5f6368; margin-top: 0; }
.avertissement { background: #fff4e5; border-left: 4px solid #e65100; padding: 10px 14px; margin: 16px 0; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #e5e5e5; vertical-align: top; }
th { background: #f5f5f7; }
.clair { color: #8a8a8a; }
code, pre { font-family: Consolas, "Cascadia Mono", monospace; font-size: 13px; }
td code { word-break: break-all; }
pre { background: #f7f7f8; border: 1px solid #e5e5e5; padding: 12px; white-space: pre-wrap;
      word-break: break-word; }
.empreinte { color: #5f6368; font-size: 12px; word-break: break-all; }
@media print { body { margin: 0; } pre { page-break-inside: avoid; } }
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


def generer(conversation, options, t, version, libelle_type, maintenant=None, utilisateur=None):
    """conversation : objet Conversation ; options : Options ; t : Traducteur ; libelle_type(type, valeur)."""
    e = html.escape
    maintenant = maintenant or datetime.datetime.now().timestamp()
    utilisateur = utilisateur or utilisateur_windows()
    moteur = conversation.moteur
    jetons = list(moteur.valide)  # seuls les jetons réellement envoyés (validés) sont rapportés
    titre = e(t("rp_titre", c=conversation.nom))

    lignes = [
        "<!DOCTYPE html>",
        f'<html lang="{t.langue}"><head><meta charset="utf-8">',
        f"<title>{titre}</title><style>{STYLE}</style></head><body>",
        f"<h1>{titre}</h1>",
        f"<p class=\"meta\">{e(t('rp_genere', d=_date(maintenant), u=utilisateur, v=version))}</p>",
        f"<div class=\"avertissement\">{e(t('rp_avertissement'))}</div>",

        f"<h2>{e(t('rp_conversation'))}</h2><table>",
        f"<tr><th>{e(t('rp_nom'))}</th><td>{e(conversation.nom)}</td></tr>",
        f"<tr><th>{e(t('rp_creee'))}</th><td>"
        f"{e(_date(conversation.cree) if conversation.cree else t('rp_inconnue'))}</td></tr>",
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

        f"<h2>{e(t('rp_elements'))}</h2><table>",
        f"<tr><th>{e(t('col_jeton'))}</th><th>{e(t('col_valeur'))}</th><th>{e(t('col_type'))}</th>"
        f"<th>{e(t('rp_statut'))}</th></tr>",
    ]
    for j in jetons:
        type_, valeur = moteur.valide[j]
        clair = j in moteur.exclus
        statut = t("rp_statut_clair") if clair else t("rp_statut_masque")
        classe = ' class="clair"' if clair else ""
        lignes.append(f"<tr{classe}><td><code>{e(j)}</code></td><td><code>{e(valeur)}</code></td>"
                      f"<td>{e(libelle_type(type_, valeur))}</td><td>{e(statut)}</td></tr>")
    if not jetons:
        lignes.append(f"<tr><td colspan=\"4\">{e(t('rp_aucun_element'))}</td></tr>")
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
