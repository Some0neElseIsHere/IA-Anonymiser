# IA-Anonymiser

Masque les données personnelles avant d'envoyer un texte à un assistant IA (Claude, etc.), puis restaure les vraies valeurs dans la réponse.

Détecté automatiquement : e-mails, téléphones (France et international), numéros de carte, IBAN, adresses IP.
Termes à indiquer soi-même : noms, entreprises, adresses (un par ligne).

## Application de presse-papiers (recommandée)

Sans dépendance, Python 3 suffit pour la lancer :

```
python clip_anon.py
```

- **Anonymiser le presse-papiers** : remplace les données sensibles du texte copié.
- **Restaurer le presse-papiers** : remet les vraies valeurs dans un texte copié depuis la réponse de l'IA.
- **Mode automatique** : traite tout ce que vous copiez (désactivé par défaut).

Les correspondances restent en mémoire tant que la fenêtre est ouverte.

## Exécutable Windows

Le workflow `.github/workflows/build-exe.yml` compile `Anonymiseur.exe` sur une machine Windows. Lancez-le depuis l'onglet **Actions**, puis téléchargez l'artefact.

## Version web locale

```
python app.py
```

Puis ouvrir http://127.0.0.1:8765. Le serveur n'écoute que sur la machine locale.

## Limites

Détection par motifs : elle ne reconnaît pas les noms qui ne sont pas listés. Relisez le texte anonymisé avant de l'envoyer.
