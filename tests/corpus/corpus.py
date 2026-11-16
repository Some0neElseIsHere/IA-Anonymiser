"""Batterie permanente sur des journaux réels : non-régression du moteur.

Les journaux (Windows, Linux, Sentinel, Entra ID…) sont récupérés depuis des dépôts publics, chacun à un
commit précis (sources.json) : ils ne sont pas copiés dans ce dépôt. Pour chaque fichier, reference.json
garde ce que le moteur masquait lors de la dernière mise à jour, sous forme d'empreintes (aucune valeur en
clair). Le test échoue si :
  - une valeur masquée auparavant ne l'est plus ;
  - une valeur sensible connue (vérité terrain : comptes, machines, IP des événements Windows, UPN, noms
    affichés, IP et appareils des journaux Entra ID) part en clair alors qu'elle était masquée ;
  - la restauration ne redonne plus le texte d'origine ;
  - un fichier prend plus de 15 secondes (expression qui s'emballe).
Les nouvelles valeurs masquées sont seulement signalées : à vérifier, puis à accepter avec --maj.

    python tests/corpus/corpus.py            # vérifier
    python tests/corpus/corpus.py --maj      # accepter l'état actuel comme nouvelle référence
"""
import argparse
import collections
import csv
import hashlib
import io
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.request
import zipfile

ICI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ICI, "..", ".."))

from fichiers import FichierIllisible, decoder  # noqa: E402
from moteur import TYPES_AUTO, Anonymiseur  # noqa: E402

MAX_LIGNES, MAX_CARACTERES, MAX_EVENEMENTS = 2000, 400_000, 1500
DUREE_MAX = 15.0
csv.field_size_limit(10 ** 8)


# --------------------------------------------------------------------------- récupération
def _motif_sparse(chemin):
    return "/" + re.sub(r"([\[\]!#?])", r"\\\1", chemin)


def recuperer(sources, cache):
    """Clone partiel de chaque dépôt au commit indiqué, seulement les fichiers utiles."""
    for s in sources:
        dossier = os.path.join(cache, s["nom"])
        marque = os.path.join(dossier, ".corpus-commit")
        attendu = s["commit"] + "\n" + "\n".join(s["fichiers"])
        if os.path.exists(marque) and open(marque, encoding="utf-8").read() == attendu:
            continue
        os.makedirs(dossier, exist_ok=True)
        git = ["git", "-C", dossier, "-c", "advice.detachedHead=false"]
        if not os.path.isdir(os.path.join(dossier, ".git")):
            subprocess.run(git + ["init", "-q"], check=True)
            subprocess.run(git + ["remote", "add", "origin", f"https://github.com/{s['depot']}.git"], check=True)
        subprocess.run(git + ["sparse-checkout", "set", "--no-cone"] + [_motif_sparse(f) for f in s["fichiers"]],
                       check=True)
        if subprocess.run(git + ["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", s["commit"]]).returncode:
            # certains serveurs refusent de servir un commit par son identifiant : la branche par défaut, puis le commit
            subprocess.run(git + ["fetch", "-q", "--depth", "200", "--filter=blob:none", "origin", "HEAD"], check=True)
        subprocess.run(git + ["checkout", "-q", s["commit"]], check=True)
        if s.get("lfs"):  # fichiers stockés avec Git LFS : le dépôt ne contient qu'un pointeur
            for racine, _, fichiers in os.walk(dossier):
                if ".git" in racine.replace("\\", "/").split("/"):
                    continue
                for nom in fichiers:
                    chemin = os.path.join(racine, nom)
                    with open(chemin, "rb") as f:
                        debut = f.read(40)
                    if debut.startswith(b"version https://git-lfs"):
                        relatif = os.path.relpath(chemin, dossier).replace("\\", "/")
                        url = f"https://media.githubusercontent.com/media/{s['depot']}/{s['commit']}/{relatif}"
                        with urllib.request.urlopen(url, timeout=60) as r, open(chemin, "wb") as f:
                            f.write(r.read())
        open(marque, "w", encoding="utf-8").write(attendu)
        print(f"récupéré : {s['depot']}@{s['commit'][:7]}", flush=True)


# --------------------------------------------------------------------------- préparation
def _couper(texte):
    texte = texte.replace("\r\n", "\n")
    return "\n".join(texte.split("\n")[:MAX_LIGNES])[:MAX_CARACTERES]


# Événements Windows (OTRF) : champs dont la valeur doit disparaître
CHAMPS_WINDOWS = ["SubjectUserName", "TargetUserName", "SubjectDomainName", "TargetDomainName", "Hostname",
                  "IpAddress", "SourceAddress", "DestAddress", "WorkstationName", "User", "TargetServerName",
                  "AccountName", "SamAccountName", "SourceIp", "DestinationIp", "SourceHostname", "DestinationHostname",
                  "ClientAddress", "TargetOutboundUserName", "Workstation"]
GENERIQUES = {"-", "WORKGROUP", "NT AUTHORITY", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE",
              "NT AUTHORITY\\NETWORK SERVICE", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "LocalSystem",
              "0.0.0.0", "::", "0:0:0:0:0:0:0:1", "1.2.3.4", "127.0.0.1", "::1", "ANONYMOUS LOGON",
              "Window Manager", "Font Driver Host"}


def _generique(v):
    return (v in GENERIQUES or re.fullmatch(r"S-1-(0-0|5-\d{1,2}|5-32-\d+)", v) is not None
            or v.startswith(("DWM-", "UMFD-", "NT SERVICE\\", "Window Manager\\", "Font Driver Host\\")))


def _evenements_windows(texte):
    """Journal JSON d'événements Windows (une ligne par événement) → texte comme dans l'Observateur, et vérité."""
    lignes = [json.loads(x) for x in texte.splitlines() if x.strip()]
    if not lignes or not all(isinstance(e, dict) and "EventID" in e for e in lignes[:20]):
        return None
    if len(lignes) > MAX_EVENEMENTS:
        lignes = sorted(random.Random(1).sample(lignes, MAX_EVENEMENTS), key=lambda e: str(e.get("TimeCreated", "")))
    blocs, verite = [], set()
    for e in lignes:
        message = str(e.get("Message") or "").replace("\r\n", "\n")
        blocs.append(f'{e.get("TimeCreated")} {e.get("Hostname")} {e.get("Channel")} {e.get("EventID")}\n{message}\n')
        for k in CHAMPS_WINDOWS:
            v = e.get(k)
            if isinstance(v, str) and v.strip() and not _generique(v.strip()):
                verite.add(v.strip())
    return "\n".join(blocs)[:MAX_CARACTERES], verite


# Journaux Entra ID : champs dont la valeur doit disparaître (nom de clé ou de colonne, sans espaces ni _)
CLES_ENTRA = {"userprincipalname", "username", "alternatesigninname", "signinidentifier", "userids", "actorupn",
              "user", "userdisplayname", "identity", "actordisplayname", "ipaddress", "clientip", "actoripaddress",
              "ipaddress(seenbyresource)", "devicename", "calleripaddress", "ipaddressfromresourceprovider",
              "hometenantname", "resourcetenantname", "authdetail", "multifactorauthenticationauthdetail",
              "networknames"}
NEUTRES = {"", "-", "null", "<null>", "none", "n/a", "unknown", "not available", "*redacted*", "{}", "[]", "true",
           "false", "0.0.0.0"}
GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _norme(k):
    return re.sub(r"[\s_]", "", (k or "").lower())


def _ajouter(verite, cle, valeur, parent):
    if not isinstance(valeur, str):
        return
    v = valeur.strip()
    if v.lower() in NEUTRES or GUID.match(v) or len(v) < 3 or "PLACEHOLDER" in v:
        return
    n = _norme(cle)
    if n in ("authdetail", "multifactorauthenticationauthdetail") and re.fullmatch(r"[A-Za-z]+", v):
        return  # état de la MFA (« Denied », « Succeeded »), pas un appareil
    if n in CLES_ENTRA or (n == "displayname" and parent in ("devicedetail", "user")) or (n == "userid" and "@" in v):
        verite.add(v)


def _parcourir(o, verite, parent=""):
    if isinstance(o, dict):
        for k, v in o.items():
            if _norme(k) == "networknames" and isinstance(v, list):  # emplacements nommés
                for x in v:
                    _ajouter(verite, "networknames", x, parent)
            if isinstance(v, (dict, list)):
                _parcourir(v, verite, _norme(k))
            elif isinstance(v, str) and v.strip()[:1] in "{[":
                try:
                    _parcourir(json.loads(v), verite, _norme(k))
                    continue
                except ValueError:
                    pass
            _ajouter(verite, k, v, parent)
    elif isinstance(o, list):
        for x in o:
            _parcourir(x, verite, parent)


def _verite_entra(texte):
    verite = set()
    if texte.lstrip()[:1] in "{[" or texte.lstrip().startswith('{"'):
        for bloc in re.split(r"\n\s*\n(?=[{\[])", texte):
            try:
                _parcourir(json.loads(bloc), verite)
            except ValueError:
                for ligne in bloc.splitlines():
                    try:
                        _parcourir(json.loads(ligne), verite)
                    except ValueError:
                        pass
    else:
        try:
            for ligne in csv.DictReader(io.StringIO(texte)):
                _parcourir(ligne, verite)
        except csv.Error:
            pass
    return verite


def preparer(sources, cache):
    """{nom: (texte, vérité)} : le texte tel qu'un utilisateur le collerait, les valeurs qui doivent disparaître."""
    corpus = {}
    for s in sources:
        racine = os.path.join(cache, s["nom"])
        chemins = sorted({os.path.join(dp, f) for dp, _, fs in os.walk(racine) if "/.git" not in dp.replace("\\", "/")
                          for f in fs if f != ".corpus-commit"})
        if s.get("assembler"):  # petits exemples d'un même dépôt : un seul texte
            morceaux = []
            for p in chemins:
                try:
                    morceaux.append(decoder(open(p, "rb").read())[0])
                except FichierIllisible:
                    pass
            texte = "\n\n".join(morceaux)
            corpus[s["nom"]] = (_couper(texte), _verite_entra(texte))
            continue
        for p in chemins:
            relatif = os.path.relpath(p, racine).replace("\\", "/")
            if p.endswith(".zip"):
                with zipfile.ZipFile(p) as z:
                    for membre in sorted(z.namelist()):
                        if membre.endswith("/"):
                            continue
                        try:
                            texte = decoder(z.read(membre))[0]
                        except FichierIllisible:
                            continue
                        nom = f"{s['nom']}/{os.path.basename(p)[:-4]}/{os.path.basename(membre)}"
                        windows = None
                        try:
                            windows = _evenements_windows(texte)
                        except ValueError:
                            pass
                        corpus[nom] = windows or (_couper(texte), set())
                continue
            try:
                texte = decoder(open(p, "rb").read())[0]
            except FichierIllisible:
                continue
            if p.endswith(".md"):  # documentation : seulement les exemples JSON
                texte = "\n\n".join(b for b in re.findall(r"```(?:json|http)?\n(.*?)```", texte, re.S) if "{" in b)
            texte = _couper(texte)
            verite = _verite_entra(texte) if s["nom"].startswith("entra") or "Entra ID" in relatif \
                or re.search(r"(?i)sign_?in_?logs|auditlogs|azure_?ad", relatif) else set()
            corpus[f"{s['nom']}/{relatif}"] = (texte, verite)
    return corpus


# --------------------------------------------------------------------------- analyse
def _empreinte(*parties):
    return hashlib.sha256("\x00".join(parties).encode("utf-8")).hexdigest()[:12]


def _present(valeur, texte):
    return re.search(r"(?<![\w.@$-])" + re.escape(valeur) + r"(?![\w@$-]|\.\w)", texte, re.I) is not None


def analyser(texte, verite):
    a = Anonymiseur("fr")
    debut = time.perf_counter()
    r = a.anonymiser(texte, [], TYPES_AUTO, [])
    duree = time.perf_counter() - debut
    a.valider()
    valeurs = {}
    for j in a.jetons():
        type_, v = a.info(j)
        valeurs[f"{type_}:{_empreinte(type_, v)}"] = (type_, v)
    fuites = {_empreinte(v): v for v in verite if _present(v, r.texte)}
    restaure = a.restaurer(r.texte).texte
    # Exact, ou à la casse près : une même valeur écrite SRV01 puis srv01 a un seul jeton, restauré sous une forme
    return {"texte": _empreinte(texte), "aller_retour": restaure == texte,
            "aller_retour_casse": restaure.casefold() == texte.casefold(),
            "masques": valeurs, "fuites": fuites, "duree": duree, "verite": len(verite)}


# --------------------------------------------------------------------------- comparaison
def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--maj", action="store_true", help="enregistrer l'état actuel comme référence")
    p.add_argument("--cache", default=os.environ.get("CORPUS_CACHE", os.path.join(ICI, "..", "..", ".corpus")))
    args = p.parse_args()
    sources = json.load(open(os.path.join(ICI, "sources.json"), encoding="utf-8"))["sources"]
    chemin_ref = os.path.join(ICI, "reference.json")
    reference = json.load(open(chemin_ref, encoding="utf-8")) if os.path.exists(chemin_ref) else {}

    recuperer(sources, args.cache)
    corpus = preparer(sources, args.cache)
    erreurs, nouveautes, resultats = [], collections.defaultdict(list), {}
    total_valeurs = total_verite = total_fuites = 0
    debut = time.perf_counter()
    for nom, (texte, verite) in sorted(corpus.items()):
        r = analyser(texte, verite)
        resultats[nom] = r
        total_valeurs += len(r["masques"])
        total_verite += r["verite"]
        total_fuites += len(r["fuites"])
        if r["duree"] > DUREE_MAX:
            erreurs.append(f"{nom} : {r['duree']:.1f} s (maximum {DUREE_MAX:.0f} s)")
        ref = reference.get(nom)
        if args.maj or ref is None:
            if ref is None and not args.maj:
                erreurs.append(f"{nom} : absent de reference.json (lancer avec --maj)")
            continue
        if ref["texte"] != r["texte"]:
            erreurs.append(f"{nom} : le fichier source a changé (commit de sources.json ?)")
            continue
        if ref["aller_retour"] and not r["aller_retour"]:
            erreurs.append(f"{nom} : la restauration ne redonne plus le texte d'origine")
        elif ref.get("aller_retour_casse", True) and not r["aller_retour_casse"]:
            erreurs.append(f"{nom} : la restauration ne redonne plus le texte d'origine, même à la casse près")
        perdus = set(ref["masques"]) - set(r["masques"])
        if perdus:
            par_type = collections.Counter(h.split(":")[0] for h in perdus)
            erreurs.append(f"{nom} : {len(perdus)} valeur(s) masquée(s) auparavant ne le sont plus "
                           f"({', '.join(f'{t} : {n}' for t, n in par_type.most_common())})")
        nouvelles_fuites = set(r["fuites"]) - set(ref["fuites"])
        if nouvelles_fuites:
            exemples = sorted(r["fuites"][h] for h in nouvelles_fuites)
            erreurs.append(f"{nom} : {len(exemples)} valeur(s) sensible(s) en clair alors qu'elles étaient masquées : "
                           + ", ".join(repr(v) for v in exemples[:6]) + (" …" if len(exemples) > 6 else ""))
        for h in set(r["masques"]) - set(ref["masques"]):
            nouveautes[nom].append(r["masques"][h])
    for nom in set(reference) - set(corpus):
        erreurs.append(f"{nom} : dans reference.json mais plus dans le corpus")

    lignes = [f"Corpus : {len(corpus)} fichiers, {total_valeurs} valeurs masquées, "
              f"vérité terrain : {total_verite - total_fuites}/{total_verite} masquées, "
              f"{time.perf_counter() - debut:.0f} s d'analyse."]
    if nouveautes:
        lignes.append(f"Nouvelles valeurs masquées dans {len(nouveautes)} fichier(s), à vérifier puis accepter avec --maj :")
        for nom, vals in sorted(nouveautes.items(), key=lambda x: -len(x[1]))[:25]:
            exemples = ", ".join(f"{t}:{v[:40]}" for t, v in sorted(vals)[:4])
            lignes.append(f"  + {len(vals):4}  {nom}  ({exemples})")
    if erreurs:
        lignes.append(f"{len(erreurs)} RÉGRESSION(S) :")
        lignes += [f"  ✗ {e}" for e in erreurs[:200]]
    print("\n".join(lignes))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write("### Batterie sur journaux réels\n\n```\n" + "\n".join(lignes) + "\n```\n")

    if args.maj:
        nouvelle = {nom: {"texte": r["texte"], "aller_retour": r["aller_retour"],
                          "aller_retour_casse": r["aller_retour_casse"],
                          "masques": sorted(r["masques"]), "fuites": sorted(r["fuites"])}
                    for nom, r in sorted(resultats.items())}
        with open(chemin_ref, "w", encoding="utf-8") as f:
            json.dump(nouvelle, f, ensure_ascii=False, separators=(",", ":"), indent=0)
        print(f"reference.json mis à jour ({len(nouvelle)} fichiers).")
        return 0
    return 1 if erreurs else 0


if __name__ == "__main__":
    sys.exit(main())
