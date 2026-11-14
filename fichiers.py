"""Lecture d'un fichier de journal pour l'anonymiser : encodage détecté, fichiers binaires refusés."""
import codecs
import os
import re

EXTENSIONS_BINAIRES = {".evtx", ".etl", ".evt", ".zip", ".7z", ".gz", ".rar", ".exe", ".dll", ".pdf", ".docx",
                       ".xlsx", ".pptx", ".png", ".jpg", ".jpeg", ".gif", ".pcap", ".pcapng", ".dmp", ".bin"}
GROS_FICHIER = 20 * 1024 * 1024  # au-delà, on demande confirmation (environ 10 s de traitement)


class FichierIllisible(Exception):
    """Le fichier n'est pas du texte : .evtx, archive, image, document Office…"""


def decoder(octets):
    """Texte et nom de l'encodage : UTF-8 (avec ou sans BOM), UTF-16 (exports PowerShell), sinon Windows-1252."""
    if octets.startswith(codecs.BOM_UTF8):
        return octets[3:].decode("utf-8", errors="replace"), "UTF-8"
    if octets.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return octets.decode("utf-16", errors="replace"), "UTF-16"
    debut = octets[:4096]
    # UTF-16 sans BOM : un octet nul sur deux (texte latin)
    if len(debut) >= 8 and debut[1::2].count(0) > len(debut) // 4 and debut[0::2].count(0) < len(debut) // 16:
        return octets.decode("utf-16-le", errors="replace"), "UTF-16"
    if b"\x00" in debut:
        raise FichierIllisible("binaire")
    try:
        return octets.decode("utf-8"), "UTF-8"
    except UnicodeDecodeError:
        return octets.decode("cp1252", errors="replace"), "Windows-1252"


def lire(chemin):
    """(texte, encodage) ; FichierIllisible si ce n'est pas un fichier texte."""
    if os.path.splitext(chemin)[1].lower() in EXTENSIONS_BINAIRES:
        raise FichierIllisible("extension")
    with open(chemin, "rb") as f:
        octets = f.read()
    texte, encodage = decoder(octets)
    if "\x00" in texte[:4096]:
        raise FichierIllisible("binaire")
    return texte.replace("\r\n", "\n").replace("\r", "\n"), encodage


def assembler(morceaux):
    """Plusieurs fichiers déposés d'un coup : un en-tête « ==> nom <== » avant chacun, comme tail ou head."""
    if len(morceaux) == 1:
        return morceaux[0][1]
    return "\n".join(f"==> {re.split(r'[\\\\/]', nom)[-1]} <==\n{texte.rstrip(chr(10))}\n" for nom, texte in morceaux)
