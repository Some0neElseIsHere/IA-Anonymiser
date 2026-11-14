**IA-Anonymiser** : masquez vos données personnelles avant de les envoyer à une IA (Claude, ChatGPT…), puis retrouvez les vraies valeurs dans sa réponse. Tout reste sur votre poste.

### Installation

1. Téléchargez **`IA-Anonymiser-vX.Y.Z.exe`** ci-dessous. `IA-Anonymiser.exe` est le même programme, sans numéro dans son nom.
2. Lancez-le : aucune installation, aucun droit administrateur.
3. Au premier lancement, Windows peut afficher « Windows a protégé votre ordinateur », car l'exe n'est pas signé : cliquez sur **Informations complémentaires**, puis **Exécuter quand même**.

Pour mettre à jour, remplacez simplement l'ancien exe : vos réglages et vos conversations, rangés dans `%APPDATA%\IA-Anonymiser`, sont conservés.

### Nouveautés de cette version

- **v1.10.3** : **un seul ascenseur pour les deux zones**. Dans « Anonymiser mon texte » et « Restaurer la réponse de l'IA », faire défiler une zone (molette, ascenseur ou clavier) fait défiler l'autre. Les deux restent alignées sur la même ligne, même si les jetons sont plus courts que les valeurs d'origine : chaque ligne du texte original reste en face de sa version anonymisée.

- **v1.10.2** : détection plus fiable, corrigée grâce à une campagne de tests massifs (10 000 documents générés : logs Windows, Linux, pare-feu, AD, SQL, tickets, mails, en français et en anglais) :
  - **noms avec ou sans accents** : un terme saisi « Marc Lefèvre » masque aussi « Marc Lefevre » et « MARC LEFEVRE », sous le même jeton ;
  - **numéros sur plusieurs lignes** : un numéro de sécurité sociale, de téléphone ou un IBAN ne peut plus « déborder » sur la ligne suivante et avaler un morceau de texte ;
  - **chemins pris pour des mots de passe** : `PWD=/home/app` ou `PATH=C:\Windows` ne sont plus masqués comme des secrets ;
  - **jeton déjà présent dans le texte** : si le texte collé contient lui-même un `[IP_1]` (par exemple une ancienne réponse de l'IA), la numérotation l'évite pour ne pas créer de confusion.
  - **scénario de bout en bout** : à chaque modification, la vraie application est désormais pilotée automatiquement sous Windows comme par un utilisateur (accueil, collage, copie pour l'IA, restauration, jeton personnalisé, rapport, épinglage, langue, thème, log de 3 000 lignes), puis relancée pour vérifier que tout est conservé et chiffré.

- **v1.10.1** : les raccourcis clavier globaux de la v1.10.0 sont retirés : copier, appuyer sur le raccourci puis coller restait trop de manipulations. Le fonctionnement redevient celui de la v1.9.0.

- **v1.10.0** : **raccourcis clavier globaux**, actifs dans toutes les applications, même quand IA-Anonymiser est en arrière-plan :
  - **Ctrl+Alt+A** : le texte copié est anonymisé directement dans le presse-papiers, prêt à coller dans l'IA (consigne et annonces de changement de jeton comprises) ;
  - **Ctrl+Alt+R** : la réponse de l'IA copiée est restaurée dans le presse-papiers, avec les vraies valeurs ;
  - une petite notification en bas à droite de l'écran indique le nombre d'éléments masqués ou restaurés, et signale les jetons inconnus ;
  - la conversation sélectionnée est utilisée, l'envoi est enregistré pour le rapport ;
  - Options → Général : autre jeu de raccourcis (Ctrl+Maj+F9 / F10) ou désactivation. Un raccourci déjà pris par une autre application est signalé.

- **v1.9.0** : **jeton personnalisé pour les termes permanents**. Dans Options → Termes permanents, chaque terme peut recevoir un jeton parlant : « Acme Industries » devient `[ENTREPRISE]` au lieu de `[NOM_1]`, pour que l'IA comprenne de quoi il s'agit.
  - **changement annoncé à l'IA** : si le terme a déjà été envoyé sous un autre jeton dans une conversation, le « Copier pour l'IA » suivant ajoute en tête : « Changement de jeton : [NOM_1] s'appelle désormais [ENTREPRISE]. C'est le même élément. » L'annonce n'est faite qu'une fois, et l'ancien jeton reste restauré dans les anciennes réponses ;
  - **saisie mise en forme** : « Client principal » devient `CLIENT_PRINCIPAL`. Un jeton déjà pris par un autre terme, ou qui ressemble à un jeton automatique (`NOM_3`), est refusé avec un message ;
  - **restauration tolérante** : `[entreprise]` ou la forme échappée en Markdown sont reconnus.

- **v1.8.1** : écran d'accueil simplifié : le principe en trois mots (Masquez, Envoyez, Restaurez) et le bouton Commencer. La saisie des termes au premier lancement est retirée : les explications détaillées sont dans les zones vides.

- **v1.8.0** : prise en main pour un nouvel utilisateur :
  - **consignes dans les zones vides** : tant que « Texte original » ou « Réponse de l'IA » est vide, la zone affiche en gris les trois étapes à suivre. Elles disparaissent dès qu'on colle ou qu'on tape ;
  - **écran d'accueil**, affiché une seule fois, à la première installation.

- **v1.7.3** : Options → Détection : une petite icône « i », assortie au thème et avec une info-bulle, remplace le lien « Voir l'expression ».

- **v1.7.2** :
  - **Options** : onglets dans l'ordre Général, Détection, Motifs personnalisés, Termes permanents, Consigne pour l'IA. La fenêtre s'ouvre sur Général ;
  - **Détection** : pour chaque type, une fenêtre montre les expressions régulières appliquées, la sensibilité à la casse et les règles particulières (extensions de domaine acceptées, comptes système exclus, partie masquée…). Le texte se copie.

- **v1.7.1** : la fenêtre Options s'ouvrait très large, puis rétrécissait lentement et par à-coups en passant sur l'onglet Motifs. Sa taille est maintenant fixe.

- **v1.7.0** :
  - **rapport : envois en clair signalés**. Chaque envoi est vérifié ; une valeur retrouvée en clair (terme ajouté après coup, envoi fait avec une ancienne version…) est surlignée en rouge avec le numéro de l'envoi, et comptée en tête du rapport ;
  - **DN Active Directory masqué partie par partie** : `CN=Sophie Bernard,OU=Compta,DC=acme,DC=local` devient `CN=[NOM_3],OU=Compta,[DN_1]`. Le nom garde le jeton qu'il a ailleurs dans la conversation : l'IA sait de qui il s'agit. Au passage, `DC=local` n'avale plus la suite de la phrase ;
  - **compte dans une URL** masqué : `https://deploy:…@` devient `https://[COMPTE_2]:[SECRET_1]@` ;
  - **motifs personnalisés avec un titre** (« Postes de travail », « Tickets »…), modifiables d'un clic. Le titre apparaît comme type dans l'onglet 3 et dans le rapport ;
  - **aide sur le moteur d'expressions régulières** : celui de Python, compatible avec `-match` de PowerShell. La syntaxe .NET `(?<v>…)` est acceptée.

- **v1.6.3** : correction de la v1.6.2 : un log de 3 000 lignes prenait 3,4 s à traiter au lieu de 0,4 s. Un test de performance bloque désormais toute version trop lente.

- **v1.6.2** : attention, cette version est lente sur les gros logs : préférez la v1.6.3.
  - **une valeur déjà masquée l'est partout** dans la conversation, même sans contexte : `slefevre`, masqué dans `C:\Users\slefevre`, l'est aussi dans « user slefevre » ; un mot de passe recopié plus tard dans une phrase est masqué lui aussi ;
  - **comptes en clé=valeur** : `User Id=`, `uid=`, `user=`, `login=`, `sAMAccountName=`.

- **v1.6.1** : rapport :
  - **valeurs d'origine** dans le tableau des éléments, avec un avertissement « document confidentiel » ;
  - **compte Windows** qui a généré le rapport (`DOMAINE\utilisateur`) dans le sous-titre ;
  - tableau de résumé par type retiré.

- **v1.6.0** : **rapport de preuve**. Onglet 3 → Exporter le rapport…, ou clic droit sur la conversation. Une page HTML, imprimable en PDF, avec la conversation, les réglages actifs, les éléments masqués et le texte exact de chaque envoi à l'IA, daté et accompagné de son empreinte SHA-256. Les envois sont enregistrés à chaque « Copier pour l'IA » à partir de cette version.

- **v1.5.0** : conversations **épinglées** (clic droit → Épingler) et **classées comme dans Claude** : Épinglées, Aujourd'hui, Hier, puis une rubrique par date (« 9 nov. »), selon la dernière activité. Le passage à minuit est pris en compte sans relancer l'application.

- **v1.4.1** : les nouvelles conversations s'ajoutent en haut de la liste.

- **v1.4.0** : **détection pour administrateurs** :
  - **secrets**, dont seule la valeur est masquée (`password=[SECRET_1]`) : `password=`, `pwd:`, `token=`, `api_key=`, chaînes de connexion, `Authorization: Bearer`, identifiants dans les URL, clés AWS, GitHub, GitLab, Slack, OpenAI, Anthropic et Google, jetons JWT, clés privées ;
  - **comptes** (`ACME\utilisateur`, `C:\Users\…`, `/home/…`), **DN** Active Directory et **SID** Windows ;
  - **motifs personnalisés** (expressions régulières) dans les options, pour vos conventions de nommage ;
  - **noms de domaine limités aux vraies extensions** : `java.lang.NullPointerException` ou `spring.datasource.url` ne sont plus masqués ;
  - correction : à la restauration, l'antislash devant un jeton (`C:\Users\[COMPTE_1]`) n'est plus supprimé.

- **v1.3.5** : une même donnée écrite autrement reçoit le même jeton : `+33 6 12 34 56 78`, `06.12.34.56.78` et `0033612345678` ; un IBAN ou une carte avec ou sans espaces ; une adresse MAC avec `:` ou `-`.

- **v1.3.4** :
  - **clic droit → Ne pas masquer** dans les trois onglets : sur une valeur surlignée, sur un jeton ou sur une ligne du tableau. « Masquer à nouveau » fait l'inverse ;
  - Options et À propos l'un au-dessus de l'autre ; barre d'état retirée : les boutons Copier affichent « Copié ! ».

- **v1.3.3** : nouvel onglet **3. Éléments masqués** (éléments et termes de la conversation), qui libère le bas de la fenêtre ; clic droit sur une conversation pour la renommer ou la fermer.

- **v1.3.2** : bandeau du haut supprimé pour gagner de la place : le logo, Options et À propos passent dans la colonne de gauche.

- **v1.3.1** :
  - au démarrage, la colonne des conversations et la zone « Anonymiser mon texte » pouvaient être réduites à rien : corrigé ;
  - un gros log figeait l'application : 3 000 lignes se traitent maintenant en 0,3 s.

- **v1.3.0** : nouvelle interface :
  - **thème** clair, sombre ou automatique (comme Windows), dans le style de Windows 11 ;
  - **français ou anglais**, avec des jetons traduits en anglais (`[NAME_1]`, `[PHONE_1]`…) ;
  - nouvelle icône et fenêtre **À propos** (recherche de mise à jour, liens, licences) ;
  - **consigne pour l'IA** personnalisable ;
  - **conversations conservées** d'un lancement à l'autre, chiffrées avec votre compte Windows (DPAPI) ;
  - mode automatique du presse-papiers retiré.

- **v1.2.0** :
  - **plusieurs conversations**, chacune avec ses propres jetons ;
  - **Options** : choix des types masqués et **termes permanents** (nom de l'entreprise, des clients…) ;
  - nouveaux types : noms de domaine (FQDN) et adresses MAC.

- **v1.1.0** : nouvelle interface : grande fenêtre, texte original et texte anonymisé côte à côte, onglet de restauration, liste des éléments masqués, termes enregistrés. Le numéro de sécurité sociale est détecté.

- **v1.0.0** : première version : masquage des e-mails, téléphones, IBAN, cartes bancaires et adresses IP via le presse-papiers, et restauration de la réponse de l'IA.

### À savoir

- La détection repose sur des motifs : relisez le texte de droite avant de l'envoyer. Un nom de personne n'est masqué que s'il figure dans vos termes.
- Les conversations sont chiffrées avec votre compte Windows (DPAPI). Les réglages (`options.json`, dont les termes permanents et les motifs) et les rapports exportés sont en clair.
- Pour vérifier un téléchargement : `Get-FileHash .\IA-Anonymiser.exe -Algorithm SHA256`, à comparer avec `SHA256SUMS.txt`.
