# IA-Anonymiser

Masquez vos données personnelles avant de les envoyer à une IA (Claude, ChatGPT…), puis remettez les vraies valeurs dans sa réponse, en un clic. En français et en anglais, avec un thème clair ou sombre.

![Onglet Anonymiser](docs/clair-relance.png)

## Télécharger

Téléchargez **[IA-Anonymiser.exe](https://github.com/Some0neElseIsHere/IA-Anonymiser/releases/latest/download/IA-Anonymiser.exe)**, la dernière version. Aucune installation n'est nécessaire : lancez simplement le fichier.

Chaque [release](https://github.com/Some0neElseIsHere/IA-Anonymiser/releases) contient deux fois le même programme : `IA-Anonymiser.exe`, dont le lien ci-dessus mène toujours à la dernière version, et `IA-Anonymiser-vX.Y.Z.exe`, qui porte son numéro de version.

> Au premier lancement, Windows peut afficher « Windows a protégé votre ordinateur », car l'exe n'est pas signé. Cliquez sur **Informations complémentaires**, puis **Exécuter quand même**.

## Utilisation

1. **Onglet « Anonymiser mon texte »** : collez votre texte à gauche. La version anonymisée apparaît aussitôt à droite. Les éléments masqués sont surlignés en jaune.
2. Cliquez sur **Copier pour l'IA** et collez le texte dans votre conversation.
3. **Onglet « Restaurer la réponse de l'IA »** : collez la réponse de l'IA à gauche. À droite, les jetons comme `[NOM_1]` sont remplacés par les vraies valeurs. Cliquez sur **Copier**.

![Onglet Restaurer](docs/clair-restaurer.png)

### Une conversation par discussion avec l'IA

La colonne de gauche liste vos conversations. Créez-en une par discussion avec l'IA. Dans une conversation, un même élément garde toujours le même jeton, d'un message à l'autre : si Jean Dupont est `[NOM_1]` dans votre premier message, il le reste dans les suivants, et l'IA s'y retrouve. L'onglet **3. Éléments masqués** liste tous les éléments déjà masqués dans la conversation, y compris ceux des messages précédents.

**Avant de coller une réponse de l'IA, sélectionnez la bonne conversation.** Un jeton inconnu de cette conversation apparaît en rouge.

Les conversations sont conservées d'un lancement à l'autre : vous pouvez restaurer une réponse de l'IA le lendemain. Faites un clic droit sur une conversation pour la renommer ou la fermer.

### Ce qui est masqué

- **Automatiquement** : e-mails, téléphones (France et international), IBAN, cartes bancaires, numéros de sécurité sociale, adresses IP, adresses MAC, noms de domaine (FQDN, par exemple `srv01.acme.local`). Les noms de fichiers comme `rapport.pdf` ne sont pas pris pour des domaines.
- **Termes permanents** : le nom de votre entreprise, de vos clients, de vos collègues… Ils se règlent dans **Options**, sont enregistrés et s'appliquent à toutes les conversations.
- **Termes de la conversation** : un nom qui ne concerne que cette discussion. Ajoutez-le dans l'onglet **3. Éléments masqués**, ou sélectionnez-le dans le texte puis clic droit → **Masquer** (ou **Ctrl+M**). Le bouton **Toujours masquer** en fait un terme permanent.

![Onglet Éléments masqués](docs/clair-elements.png)

Pour laisser un élément en clair, faites un clic droit dessus → **Ne pas masquer**. Ça marche dans les trois onglets : sur la valeur surlignée dans votre texte, sur un jeton, ou sur une ligne du tableau des éléments masqués. Le même clic droit permet de le masquer à nouveau.

## Options

![Options](docs/options-detection.png)

- **Détection** : cochez les types de données à masquer automatiquement.
- **Termes permanents** : la liste des termes toujours masqués.
- **Consigne pour l'IA** : un texte ajouté au début de ce que vous copiez, qui demande à l'IA de garder les jetons tels quels. Vous pouvez le modifier, le désactiver ou rétablir le texte par défaut.
- **Général** :
  - la langue (automatique, français ou anglais) ;
  - le thème (automatique comme Windows, clair ou sombre) ;
  - la conservation des conversations après la fermeture.

En anglais, les jetons sont aussi traduits : `[NAME_1]`, `[PHONE_1]`, `[CARD_1]`… Les deux formes sont reconnues lors de la restauration.

![Thème sombre](docs/sombre-anonymiser.png)

## Confidentialité

- Tout se passe sur votre ordinateur : vos textes ne sont envoyés nulle part. Seul le bouton **Rechercher une nouvelle version**, dans À propos, contacte GitHub, et uniquement pour connaître le numéro de la dernière version.
- Les options et les termes permanents sont enregistrés dans `%APPDATA%\IA-Anonymiser\options.json`.
- Les conversations, qui contiennent les vraies valeurs, sont enregistrées dans `%APPDATA%\IA-Anonymiser\conversations.dat`, **chiffrées avec votre compte Windows** (DPAPI). Un autre compte, ou une copie du fichier sur un autre ordinateur, ne peut pas les lire. Vous pouvez désactiver cette conservation, ou effacer le fichier, dans **Options → Général**.

## Limites

La détection repose sur des motifs. Elle ne reconnaît pas un nom qui ne figure pas dans vos termes, une adresse postale doit être ajoutée comme terme, et un nom de machine sans point (`SRV-PAIE01`) aussi. À l'inverse, la détection des FQDN peut masquer des mots comme `ASP.NET` : faites un clic droit → **Ne pas masquer** pour les laisser en clair. **Relisez toujours le texte de droite avant de l'envoyer.**

## Vérifier le téléchargement

Chaque release contient un fichier `SHA256SUMS.txt`. Dans PowerShell :

```
Get-FileHash .\IA-Anonymiser.exe -Algorithm SHA256
```

L'empreinte affichée doit correspondre à celle indiquée dans le fichier, qui contient les deux exe.

## Publier une nouvelle version

Dans l'onglet **Actions**, ouvrez **Construction et release**, cliquez sur **Run workflow** et saisissez le numéro de version (par exemple `v1.4.0`). Les tests sont lancés, puis l'exe est compilé et publié dans une release.

## Licence

GNU GPL v3. IA-Anonymiser utilise Python (licence PSF), Tcl/Tk (licence BSD) et le thème [Sun Valley](https://github.com/rdbende/Sun-Valley-ttk-theme) (licence MIT).
