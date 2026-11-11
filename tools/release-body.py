#!/usr/bin/env python3
"""Description d'une release GitHub, tirée de docs/release-notes.md (même principe que PhishGuard).

Liens de téléchargement en tête, nouveautés de cette version seulement, installation, à savoir,
lien vers l'historique complet.
Usage : release-body.py <notes.md> <version> <owner/repo> [corps.md] [fichiers publiés, séparés par des virgules]
"""
import re
import sys


def section(texte, titre):
    m = re.search(r"^### " + re.escape(titre) + r"\s*\n(.*?)(?=^### |\Z)", texte, re.S | re.M)
    return m.group(1).strip() if m else ""


def entree(nouveautes, version):
    """Puce « - **vX.Y.Z** … » et ses lignes de suite, jusqu'à la puce de version suivante."""
    sortie, dedans = [], False
    for ligne in nouveautes.splitlines():
        if re.match(r"^- \*\*v[0-9]", ligne):
            if dedans:
                break
            dedans = ligne.startswith("- **" + version + "**")
        if dedans:
            sortie.append(ligne)
    texte = "\n".join(sortie).strip()
    # « - **v1.2.3** : texte » devient « texte » ; une liste imbriquée remonte au premier niveau
    texte = re.sub(r"^- \*\*" + re.escape(version) + r"\*\* ?:? ?", "", texte).strip()
    texte = re.sub(r"^  - ", "- ", texte, flags=re.M)
    texte = re.sub(r"^  (?=\S)", "", texte, flags=re.M)
    texte = re.sub(r"\A([^\n-][^\n]*)\n- ", r"\1\n\n- ", texte)  # ligne vide entre la phrase et la liste
    # majuscule en tête du texte et de chaque puce
    texte = re.sub(r"^(- (?:\*\*)?)(\w)", lambda m: m.group(1) + m.group(2).upper(), texte, flags=re.M)
    return texte[:1].upper() + texte[1:]


def liens(base, version, fichiers):
    if fichiers is None:  # nouvelle release : noms habituels
        fichiers = [f"IA-Anonymiser-{version}.exe", "IA-Anonymiser.exe", "SHA256SUMS.txt"]
    numerote = f"IA-Anonymiser-{version}.exe" in fichiers
    noms = {
        f"IA-Anonymiser-{version}.exe": "Exécutable (.exe)",
        "IA-Anonymiser.exe": "Même exe, sans numéro" if numerote else "Exécutable (.exe)",
        "Anonymiseur.exe": "Exécutable (.exe)",
        "SHA256SUMS.txt": "Empreintes SHA-256",
    }
    morceaux = [f"[{noms[f]}]({base}{f})" for f in noms if f in fichiers]
    if not morceaux:
        return ""
    morceaux[0] = "**⬇ Télécharger : " + morceaux[0] + "**"
    return " · ".join(morceaux)


def construire(notes, version, depot, fichiers=None):
    base = f"https://github.com/{depot}/releases/download/{version}/"
    historique = f"https://github.com/{depot}/blob/main/docs/release-notes.md"
    premiere = notes.strip().splitlines()[0]
    nouveautes = entree(section(notes, "Nouveautés de cette version"), version)
    installation = section(notes, "Installation").replace("ci-dessous", "(lien ci-dessus)")
    numerote = f"IA-Anonymiser-{version}.exe"
    if fichiers is not None and numerote not in fichiers:  # anciennes versions : un seul exe, sans numéro
        principal = next((f for f in ("IA-Anonymiser.exe", "Anonymiseur.exe") if f in fichiers), numerote)
        installation = installation.replace(
            " `IA-Anonymiser.exe` est le même programme, sans numéro dans son nom.", "")
        installation = installation.replace("IA-Anonymiser-vX.Y.Z.exe", principal)
    installation = installation.replace("vX.Y.Z", version)
    parties = [premiere, "", liens(base, version, fichiers), "",
               f"### Nouveautés de la {version}", "", nouveautes or "Voir l'historique.", "",
               f"[Historique complet des versions]({historique})", "",
               "### Installation", "", installation]
    a_savoir = section(notes, "À savoir")
    if a_savoir:
        parties += ["", "### À savoir", "", a_savoir]
    return "\n".join(parties).rstrip() + "\n"


if __name__ == "__main__":
    exiger = "--exiger" in sys.argv  # échoue si la version n'a pas d'entrée dans les notes
    sys.argv = [a for a in sys.argv if a != "--exiger"]
    chemin, version, depot = sys.argv[1:4]
    fichiers = sys.argv[5].split(",") if len(sys.argv) > 5 and sys.argv[5] else None
    with open(chemin, encoding="utf-8-sig") as f:
        notes = f.read()
    if exiger and not entree(section(notes, "Nouveautés de cette version"), version):
        sys.exit(f"docs/release-notes.md : aucune entrée « - **{version}** » dans « Nouveautés de cette version ».")
    corps = construire(notes, version, depot, fichiers)
    if len(sys.argv) > 4:
        with open(sys.argv[4], "w", encoding="utf-8", newline="\n") as f:
            f.write(corps)
    else:
        sys.stdout.buffer.write(corps.encode("utf-8"))
