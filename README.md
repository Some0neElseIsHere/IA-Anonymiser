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

La colonne de gauche liste vos conversations, classées comme dans Claude : d'abord les **épinglées**, puis **Aujourd'hui**, **Hier**, et une rubrique par date (« 9 nov. »), selon votre dernière activité dans chacune. Créez-en une par discussion avec l'IA. Dans une conversation, un même élément garde toujours le même jeton, d'un message à l'autre : si Jean Dupont est `[NOM_1]` dans votre premier message, il le reste dans les suivants, et l'IA s'y retrouve. L'onglet **3. Éléments masqués** liste tous les éléments déjà masqués dans la conversation, y compris ceux des messages précédents.

**Avant de coller une réponse de l'IA, sélectionnez la bonne conversation.** Un jeton inconnu de cette conversation apparaît en rouge.

Les conversations sont conservées d'un lancement à l'autre : vous pouvez restaurer une réponse de l'IA le lendemain. Faites un clic droit sur une conversation pour l'épingler, la renommer ou la fermer.

### Ce qui est masqué

- **Automatiquement** :
  - données personnelles : e-mails, téléphones (France et international), IBAN, cartes bancaires, numéros de sécurité sociale ;
  - réseau : adresses IP, adresses MAC, noms de domaine (FQDN, par exemple `srv01.acme.local`) ;
  - **secrets** : `password=…`, `pwd:`, `token=`, `api_key=`, chaînes de connexion, `Authorization: Bearer …`, identifiants dans une URL (`https://user:motdepasse@…`), clés AWS, GitHub, GitLab, Slack, OpenAI, Anthropic et Google, jetons JWT, clés privées. Seule la valeur est masquée (`password=[SECRET_1]`), pour que l'IA comprenne encore de quoi il s'agit ;
  - **comptes et annuaire** : `ACME\mlefevre`, le nom d'utilisateur dans `C:\Users\…` et `/home/…`, les DN Active Directory (`CN=…,OU=…,DC=…`), les SID Windows.
- **Motifs personnalisés** : vos conventions de nommage, sous forme d'expressions régulières, dans **Options → Motifs personnalisés**. Par exemple `PC-\d{4}` pour les postes, `INC-\d{4}-\d+` pour les tickets, `SRV-[A-Z]+\d*` pour les serveurs.
- **Termes permanents** : le nom de votre entreprise, de vos clients, de vos collègues… Ils se règlent dans **Options**, sont enregistrés et s'appliquent à toutes les conversations.
- **Termes de la conversation** : un nom qui ne concerne que cette discussion. Ajoutez-le dans l'onglet **3. Éléments masqués**, ou sélectionnez-le dans le texte puis clic droit → **Masquer** (ou **Ctrl+M**). Le bouton **Toujours masquer** en fait un terme permanent.

Ce qui reste volontairement en clair : les noms de fichiers (`rapport.pdf`, `backup.tar.gz`), les numéros de version, les noms de classes et les clés de configuration (`java.lang.NullPointerException`, `spring.datasource.url`), les comptes système (`NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`), les chemins de registre (`HKLM\…`) et les SID système (`S-1-5-18`).

![Onglet Éléments masqués](docs/clair-elements.png)

Pour laisser un élément en clair, faites un clic droit dessus → **Ne pas masquer**. Ça marche dans les trois onglets : sur la valeur surlignée dans votre texte, sur un jeton, ou sur une ligne du tableau des éléments masqués. Le même clic droit permet de le masquer à nouveau.

### Rapport de preuve

Pour garder une trace de ce qui a été envoyé à l'IA, cliquez sur **Exporter le rapport…** dans l'onglet **3. Éléments masqués**, ou faites un clic droit sur la conversation. Le rapport est une page HTML, lisible dans un navigateur et imprimable en PDF. Il contient :

- la date de l'export, le compte Windows qui l'a généré (`DOMAINE\utilisateur`) et la version de l'application ;
- la conversation et les réglages actifs (types détectés, nombre de termes et de motifs) ;
- chaque élément masqué : jeton, **valeur d'origine**, type, et s'il a été masqué ou laissé en clair volontairement ;
- le texte exact de chaque envoi à l'IA, tel qu'il est parti (anonymisé), avec sa date et son empreinte SHA-256.

**C'est un document confidentiel** : il réunit les valeurs d'origine de la conversation (noms, adresses, secrets…). Conservez-le dans un emplacement sécurisé. Les envois sont enregistrés à chaque « Copier pour l'IA » (ou copie depuis le texte à envoyer), à partir de la version 1.6.

## Options

![Options](docs/options-detection.png)

- **Détection** : cochez les types de données à masquer automatiquement.
- **Termes permanents** : la liste des termes toujours masqués.
- **Motifs personnalisés** : vos expressions régulières. En ajoutant un motif, vous voyez combien de fois il apparaît dans le texte en cours. Pour en créer un facilement, utilisez [regex101.com](https://regex101.com/?flavor=python) en choisissant « Python » : collez un extrait de log, écrivez le motif, et le site surligne ce qu'il trouve.
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

La détection repose sur des motifs : elle ne peut pas être parfaite.

- Un nom de personne n'est masqué que s'il figure dans vos termes. Une adresse postale doit aussi être ajoutée comme terme.
- Un nom de machine sans point (`SRV-PAIE01`) n'est masqué que par un motif personnalisé.
- Un mot de passe n'est reconnu que s'il a une forme reconnaissable (`password=…`, une clé connue…). Écrit seul au milieu d'une phrase, il ne se distingue pas d'un mot ordinaire.
- À l'inverse, un élément peut être masqué à tort : faites un clic droit → **Ne pas masquer** pour le laisser en clair. **Relisez toujours le texte de droite avant de l'envoyer.**

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
