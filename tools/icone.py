"""Génère assets/icone.png (256 px) et assets/icone.ico (16 à 256 px).

Bulle de discussion blanche dont le texte est caviardé, sur un carré arrondi en dégradé.
Usage : python tools/icone.py
"""
import os

from PIL import Image, ImageDraw

T = 1024  # dessin en grand, réduit ensuite pour un rendu net
RACINE = os.path.join(os.path.dirname(__file__), "..", "assets")


def degrade(taille, haut, bas):
    img = Image.new("RGB", (taille, taille))
    d = ImageDraw.Draw(img)
    for y in range(taille):
        for x in range(0, taille, 8):
            k = (x + y) / (2 * taille)
            c = tuple(int(haut[i] + (bas[i] - haut[i]) * k) for i in range(3))
            d.line([(x, y), (x + 8, y)], fill=c)
    return img


def dessiner():
    fond = degrade(T, (79, 70, 229), (14, 165, 233))  # indigo -> bleu ciel
    masque = Image.new("L", (T, T), 0)
    ImageDraw.Draw(masque).rounded_rectangle([0, 0, T - 1, T - 1], radius=230, fill=255)
    img = Image.new("RGBA", (T, T), (0, 0, 0, 0))
    img.paste(fond, (0, 0), masque)

    d = ImageDraw.Draw(img)
    # Ombre douce de la bulle
    ombre = Image.new("RGBA", (T, T), (0, 0, 0, 0))
    od = ImageDraw.Draw(ombre)
    od.rounded_rectangle([170, 230, 870, 720], radius=120, fill=(20, 20, 60, 70))
    od.polygon([(300, 700), (290, 860), (470, 700)], fill=(20, 20, 60, 70))
    img = Image.alpha_composite(img, ombre)
    d = ImageDraw.Draw(img)
    # Bulle
    d.rounded_rectangle([150, 200, 850, 690], radius=120, fill=(255, 255, 255, 255))
    d.polygon([(280, 670), (260, 840), (460, 670)], fill=(255, 255, 255, 255))
    # Lignes de texte : une partie lisible (gris), une partie caviardée (barres sombres)
    sombre, gris = (30, 27, 75, 255), (190, 196, 214, 255)
    d.rounded_rectangle([250, 300, 430, 370], radius=35, fill=gris)
    d.rounded_rectangle([460, 300, 750, 370], radius=35, fill=sombre)
    d.rounded_rectangle([250, 410, 750, 480], radius=35, fill=sombre)
    d.rounded_rectangle([250, 520, 520, 590], radius=35, fill=gris)
    d.rounded_rectangle([550, 520, 690, 590], radius=35, fill=sombre)
    return img


def main():
    os.makedirs(RACINE, exist_ok=True)
    grand = dessiner()
    grand.resize((256, 256), Image.LANCZOS).save(os.path.join(RACINE, "icone.png"))
    grand.resize((64, 64), Image.LANCZOS).save(os.path.join(RACINE, "icone-64.png"))
    tailles = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    images = [grand.resize((s, s), Image.LANCZOS) for s in tailles]
    images[-1].save(os.path.join(RACINE, "icone.ico"), sizes=[(s, s) for s in tailles], append_images=images[:-1])


if __name__ == "__main__":
    main()


def icone_info(couleur, texte, chemin):
    """Petite icône « i » ronde (32 px, réduite à 16 px à 100 % d'affichage)."""
    t = 256
    img = Image.new("RGBA", (t, t), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([8, 8, t - 8, t - 8], fill=couleur)
    d.ellipse([112, 52, 144, 84], fill=texte)            # point du i
    d.rounded_rectangle([114, 106, 142, 204], radius=12, fill=texte)  # barre du i
    img.resize((32, 32), Image.LANCZOS).save(chemin)


if __name__ == "__main__":
    icone_info((0, 95, 184, 255), (255, 255, 255, 255), os.path.join(RACINE, "info-clair.png"))
    icone_info((87, 200, 255, 255), (28, 28, 28, 255), os.path.join(RACINE, "info-sombre.png"))
