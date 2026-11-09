# Tri des emails de logs — Docker, lecture seule

Ce service lit une boîte IMAP dédiée, classe les rapports connus et conserve les résultats dans un volume Docker. La version 0.3 ajoute une interface web HTTPS protégée, des réglages persistants, un aperçu avant envoi et une analyse facultative avec ton abonnement ChatGPT.

La version 0.2 reconnaît aussi les rapports Proxmox VE/PBS/Mail Gateway, les alertes Wazuh individuelles, les notifications Synology de stockage, instantanés, mises à jour et sécurité, ainsi que les états d’onduleur et les compteurs Kyocera rencontrés dans la boîte. Les messages administratifs et les bulletins sont identifiés séparément.

Le bilan présente les problèmes récents regroupés et les rétablissements confirmés, sans énumérer les réussites habituelles. La période est de 24 heures par défaut. Les anciens problèmes sans confirmation de rétablissement sont comptabilisés séparément ; les détails restent dans les JSON. Un format réellement nouveau ou illisible reste visible comme point à vérifier. La reconnaissance des modèles présents n’est pas une garantie de prise en charge de tous les futurs emails possibles.

## Déploiement depuis GitHub dans Portainer

Le fichier `compose.yaml` est prévu pour une stack **Docker Standalone** déployée depuis GitHub dans Portainer. Il construit l’image depuis le dépôt, utilise les règles incluses dans cette image et ne dépend ni d’un `.env`, ni d’un fichier secret, ni d’un dossier de configuration présents sur le serveur.

Dans **Stacks → Add stack → Repository**, configure :

- Repository URL : `https://github.com/philippec78/logtriage`
- Repository reference : `refs/heads/main`
- Compose path : `compose.yaml`

Dans **Environment variables**, ajoute les valeurs suivantes :

| Variable | Valeur à renseigner |
|---|---|
| `IMAP_HOST` | Nom de ton serveur IMAP, obligatoire |
| `IMAP_USER` | Identifiant de la boîte, obligatoire |
| `IMAP_PASSWORD` | Mot de passe de la boîte ou mot de passe d’application, obligatoire |
| `IMAP_PORT` | `993` par défaut |
| `IMAP_FOLDER` | `INBOX` par défaut |

Le mot de passe est enregistré dans la configuration de la stack et transmis au conteneur comme variable d’environnement. Il reste consultable par les administrateurs Docker/Portainer ; ne le saisis pas dans le fichier Compose ni dans GitHub. Les variables saisies dans Portainer sont explicitement transmises au service par le fichier Compose.

Clique ensuite sur **Deploy the stack**. Pour une stack Git existante, actualise ses variables puis utilise **Pull and redeploy** pour récupérer le dépôt corrigé. L’image `imap-log-triage:local` est construite depuis le dépôt, pas téléchargée depuis un registre. L’option de rechargement forcé d’une image depuis un registre (**Re-pull image**) n’est pas nécessaire. Le volume `triage-data` et les protections de lecture seule sont conservés.

Le fichier utilise `pull_policy: build` afin de reconstruire le moteur et ses règles lors du déploiement. Sur Docker Swarm, il faut une image préconstruite disponible pour les nœuds ; ce fichier de construction Standalone n’est pas un fichier de déploiement Swarm.

## Interface web et connexion avec ChatGPT

Dans Portainer, ajoute ces variables **avant le redéploiement** :

| Variable | Valeur |
|---|---|
| `WEB_BIND_IP` | Adresse privée du serveur accessible depuis ton réseau ; `127.0.0.1` par défaut |
| `WEB_PUBLIC_URL` | Adresse exacte de la page, par exemple `https://192.0.2.10:8448` ; utilise l’adresse réelle de ton serveur |
| `WEB_PORT` | `8448` par défaut |
| `REPORT_TO` | Ton adresse destinataire |
| `SMTP_HOST` | Ton serveur SMTP |
| `SMTP_PORT` | `465` pour SMTP sur TLS implicite |
| `SMTP_USE_IMAP_CREDENTIALS` | `true` uniquement si tu autorises la réutilisation des identifiants IMAP |

N’utilise pas `0.0.0.0` comme adresse de publication sur une machine exposée à Internet. Cette interface d’administration est prévue pour ton réseau privé ou un accès VPN. `WEB_PUBLIC_URL` doit correspondre exactement à l’adresse ouverte, y compris son port : les contrôles d’origine, le certificat local et l’assistant ChatGPT l’utilisent.

L’identifiant web initial est `admin`. Le mot de passe aléatoire est généré dans le volume, jamais affiché dans les logs. Dans la console Portainer du conteneur, avec l’utilisateur `10001`, affiche-le avec :

```sh
cat /data/private/web-initial-password.txt
```

Tu peux aussi fournir `WEB_USER` et un `WEB_PASSWORD` d’au moins 12 caractères **lors du premier démarrage web**. Le compte est ensuite conservé dans le volume ; changer cette variable ne réinitialise pas un compte existant. Les mots de passe sont hachés avec PBKDF2 ; les fichiers privés sont en mode 0600 et leur dossier en 0700.

Le certificat HTTPS est généré localement avec le nom ou l’adresse de `WEB_PUBLIC_URL`. Ton navigateur peut demander que tu valides ce certificat local. Effectue toi-même cette validation après avoir vérifié l’adresse du serveur. Un changement du nom d’accès peut entraîner son renouvellement. Aucun contrôle TLS d’OpenAI, de l’IMAP ou du SMTP n’est désactivé.

### Utiliser la page

- **Bilan** : état de la collecte, nombre d’emails analysés et dernier bilan déterministe.
- **Réglages** : période du rapport, nombre de points, intervalle de collecte, destinataire, expéditeur, SMTP et compte/modèle ChatGPT. Les réglages d’IMAP et ses secrets restent dans Portainer.
- **Envoyer un rapport** : préparer un aperçu classique ou enrichi par ChatGPT, le relire, puis cliquer sur **Envoyer cet aperçu**. Aucun email n’est envoyé par la simple préparation.

L’aperçu est figé pendant 15 minutes. Un changement de réglages impose une nouvelle préparation. Le même aperçu n’est pas renvoyé deux fois. Si un envoi reste incertain, vérifie ta boîte : il n’est jamais réessayé automatiquement. La confirmation signifie « accepté par le SMTP », pas « livré au destinataire ».

### Autoriser ton abonnement ChatGPT

Cette intégration utilise le parcours officiel **Sign in with ChatGPT** pour les outils personnels/ouverts auto-hébergés, et non une clé API ni une session de navigateur copiée. L’accès dépend de l’éligibilité de ton compte et de ton autorisation effective.

1. Dans **Réglages → Analyse avec ChatGPT**, choisis **Ajouter un compte**, puis **Continuer avec ChatGPT**.
2. Sur ton Mac, ouvre le ZIP téléchargé, puis le fichier `logtriage-chatgpt.command`. Python 3 doit être disponible. L’assistant ouvre un retour local sur `127.0.0.1`, puis le navigateur OpenAI.
3. Connecte-toi à ChatGPT et autorise logtriage. Le code de retour est transmis au serveur par HTTPS. Les jetons d’accès et de renouvellement sont échangés et conservés uniquement sur le serveur, pas sur ton Mac.
4. Reviens dans les réglages, clique sur **Actualiser les modèles**, sélectionne un modèle de ton compte, active l’analyse puis enregistre.
5. Dans l’onglet d’envoi, coche l’analyse ChatGPT et prépare un rapport.

L’assistant est temporaire : l’autorisation doit être terminée dans les dix minutes. Le serveur renouvelle ensuite ses jetons et peut fonctionner lorsque ton Mac est éteint. Une révocation ou une session expirée peut demander une reconnexion. Les comptes enregistrés restent séparés ; tu peux en sélectionner un ou le déconnecter. En cas de révocation distante non confirmée, retire également l’accès depuis ChatGPT.

Les requêtes utilisent `https://api.openai.com/v1/responses`, avec `store:false`, `stream:true` et un modèle découvert dans le catalogue du compte connecté. Les exigences et limitations du parcours SIWC sont respectées. Le modèle peut appeler uniquement quatre fonctions locales de lecture : bilan, liste d’événements, preuves d’un événement et historique de la même tâche. Pas de shell, pas d’outil d’envoi, pas d’écriture IMAP, pas de recherche web ni de lien d’email ouvert.

Les statuts, compteurs, titres et avertissements du bilan sont conservés. L’IA ajoute des vérifications courtes rattachées aux identifiants existants ; elle ne supprime pas les faits. Ses propositions doivent être relues : leur justesse sémantique n’est pas garantie par la validation de structure. L’analyse est limitée à quatre tours et dix appels d’outils. Une erreur, une limite d’abonnement, un flux incomplet ou un résultat invalide conserve le bilan classique et affiche la raison dans l’aperçu.

Le serveur transmet à OpenAI le bilan et des extraits structurés bornés, avec retrait des liens et des secrets évidents. Les noms de serveurs et les preuves utiles peuvent rester présents ; ce filtrage ne garantit pas l’anonymisation de toute donnée. Les identifiants IMAP/SMTP et les emails bruts ne sont jamais fournis comme contexte au modèle. Les jetons ChatGPT ne sont jamais retournés à la page web.

Références officielles : [autorisation SIWC](https://developers.openai.com/siwc/token-sharing-open-source/sign-in), [serveurs auto-hébergés](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms), [modèles et requêtes](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference), [limites actuelles](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations).

## Démarrage local avec un fichier secret

Prérequis : Docker Engine et Docker Compose v2 sur ton serveur. Depuis le dossier de ce projet :

```sh
cp .env.example .env
```

Renseigne `IMAP_HOST`, `IMAP_PORT`, `IMAP_USER` et `IMAP_FOLDER` dans `.env`. La connexion utilise obligatoirement IMAP sur TLS, avec vérification du certificat du serveur, normalement sur le port 993. L’authentification utilise un identifiant et un mot de passe, ou un mot de passe d’application si ton fournisseur l’exige. OAuth2 n’est pas pris en charge dans cette version.

Crée `secrets/imap_password.txt` contenant uniquement le mot de passe, sans guillemets. Ne l’envoie pas dans un chat. Pour que seul ton utilisateur puisse traverser le dossier sur l’hôte, tout en permettant au processus du conteneur de lire le secret monté :

```sh
chmod 700 secrets
chmod 444 secrets/imap_password.txt
chmod 600 .env
docker compose -f compose.local.yaml config --quiet
docker compose -f compose.local.yaml up -d --build
docker compose -f compose.local.yaml logs --tail=50 triage
```

Le processus du conteneur utilise l’utilisateur 10001. Sur l’hôte, le fichier secret est lisible mais son dossier est réservé à ton utilisateur. Pour modifier le secret, rends d’abord le fichier modifiable (`chmod 600 secrets/imap_password.txt`), puis rétablis le mode 444 et recrée le service. Si ta plateforme Docker gère directement des secrets, tu peux remplacer le montage fichier par son mécanisme de secrets.

`compose.local.yaml` déclare le secret à la fois dans le service et au niveau général. Ne commente pas une seule des deux déclarations. Un `IMAP_PASSWORD_FILE` explicitement configuré est prioritaire sur `IMAP_PASSWORD` ; un fichier absent provoque une erreur, sans repli silencieux vers la variable.

La première collecte importe les emails reçus dans les 30 derniers jours, lus ou non lus. Les lots d’import ou de réanalyse s’enchaînent avec une courte pause jusqu’à résorption de l’attente. Ensuite, les nouveaux messages sont collectés toutes les cinq minutes. L’historique de départ est fixé lors de la première connexion réussie au dossier ; modifier `INITIAL_LOOKBACK_DAYS` après cela ne réinitialise pas cet historique. Les messages plus anciens que ce point de départ restent hors périmètre. Le compte et le dossier configurés sont les seuls consultés. Un sous-dossier n’est pas parcouru automatiquement. Pour un nom de dossier non ASCII, utilise son nom IMAP encodé en modified UTF-7.

## Consulter et récupérer les résultats

Dans Portainer, ouvre la console du conteneur puis consulte `cat /data/exports/bilan.txt` ou `cat /data/exports/summary.json`. Pour une installation locale avec le fichier secret :

```sh
docker compose -f compose.local.yaml exec triage cat /data/exports/bilan.txt
docker compose -f compose.local.yaml exec triage cat /data/exports/summary.json
docker compose -f compose.local.yaml cp triage:/data/exports ./exports
```

Le dossier `/data/exports` contient :

| Fichier | Contenu |
|---|---|
| `messages.json` | Classement de chaque email, preuves, identifiant Message-ID, empreinte et référence IMAP |
| `tasks.json` | Suivi des tâches, échecs distincts et rétablissements explicitement confirmés |
| `observations.json` | Détections de sécurité regroupées, avec dates du premier et du dernier rapport |
| `summary.json` | Compteurs généraux et rappel du mode de fonctionnement |
| `bilan.txt` | Bilan courant lisible, incluant les tâches encore en échec |
| `daily/AAAA-MM-JJ.txt` | Dernier bilan disponible pour chaque journée, en heure suisse |

Le bilan est actualisé à chaque collecte. Il affiche les problèmes des dernières 24 heures et les rétablissements récents. Les anciens problèmes sans confirmation de rétablissement sont comptabilisés à part. Les observations de faible sévérité restent dans les exports détaillés. Aucun envoi n’est programmé : tu peux préparer puis envoyer un aperçu depuis la page web, ou utiliser la commande SMTP. Un outil extérieur peut reprendre les JSON ou le bilan texte. La base locale est `/data/history.sqlite3`. Aucun corps d’email intégral ni PDF original n’est conservé dans ce volume ; les preuves sélectionnées et métadonnées peuvent toutefois contenir des noms de machines et des détails techniques.

Les références IMAP incluent une identité de compte hachée, le dossier, UIDVALIDITY et UID. Le Message-ID et l’empreinte SHA-256 sont aussi conservés. Un changement de UIDVALIDITY réimporte les références sans recompter les emails identiques. Deux messages de même Message-ID mais de contenu différent restent distincts. L’état des tâches est recalculé dans l’ordre des dates des emails pour supporter les imports tardifs ; un échec et une réussite à la même seconde maintiennent l’échec ouvert.

## Garantie de lecture seule de la boîte

Le code impose l’ouverture avec `EXAMINE` (`readonly=True`) et la récupération avec `BODY.PEEK[]`. Le collecteur ne contient aucun déplacement, suppression, ajout d’étiquette, marquage lu/non lu, envoi automatique ou appel à une IA externe. Un module SMTP séparé permet un envoi ponctuel uniquement sur commande explicite. Il n’utilise pas `CLOSE`, qui peut expurger des messages. Aucun lien fourni dans les emails n’est ouvert et aucune instruction contenue dans un email ou un PDF n’est exécutée.

La garantie porte sur les opérations du service : un autre client ou une règle du serveur peut toujours modifier la boîte. Si ton serveur permet un compte ou des droits IMAP limités à la lecture, utilise-les en complément. Il n’existe pas d’option pour activer l’écriture dans cette version.

Le système de fichiers du conteneur est aussi monté en lecture seule, à l’exception du volume local de résultats et de `/tmp`. L’interface écoute sur 8448 dans le conteneur ; sa publication est limitée à l’hôte par défaut. Les erreurs de connexion n’affichent pas les réponses détaillées du serveur ni le mot de passe.

## Règles incluses

Les réglages sont dans `config/rules.json`. Avec Portainer/Git, ils sont inclus dans l’image : modifie le fichier dans le dépôt puis redéploie la stack pour reconstruire l’image. Avec `compose.local.yaml`, le fichier est monté en lecture seule : redémarre le service après une modification :

```sh
docker compose -f compose.local.yaml restart triage
```

Une empreinte des règles et de la version du moteur déclenche la réanalyse progressive des messages encore accessibles dans la période de collecte. Les emails supprimés entre-temps ne peuvent pas être réanalysés ; leur ancien résultat reste conservé. Les emails et les observations ne sont pas multipliés par cette réanalyse.

- **Synology Backup / C2** : succès explicite ou échec explicite ; un transfert nul, isolément, ne signifie pas échec. Les modèles français fournis sont couverts.
- **Planificateur Synology** : code de sortie 0 comme succès signalé ; code non nul ou erreur explicite comme échec. Le libellé « Sortie/erreur standard » n’est pas une erreur.
- **Active Backup for Business et réplication** : une simple fin annoncée reste `fin_annoncee` et ne clôture pas automatiquement un incident. Une cause absente, comme `%ERROR_REASON%`, est signalée.
- **Proxmox Backup Server** : les échecs de garbage collection sont regroupés par serveur et datastore. Chaque occurrence et chaque cause restent disponibles. Ces emails ne suffisent pas à conclure à une corruption des sauvegardes.
- **Wazuh** : extraction des groupes hôte/règle/niveau et des agents déconnectés. Les parties texte et HTML ne sont pas additionnées. Les nombres sont des détections et ne représentent pas des incidents uniques. Une absence de détection dans un rapport ultérieur ne résout pas automatiquement une observation ancienne.
- **OpenVAS** : séparation de la fin du scan et des observations. Lecture des PDF textuels, extraction des scores CVSS explicitement observés et des constats des modèles fournis. Une formulation « aucune CVE au seuil » ne devient jamais « aucun problème ».
- **Autres formats** : `a_verifier`, sans clôture automatique d’un incident.

Les règles sont adaptées aux exemples reçus, pas à tous les formats possibles de ces produits. Les PDF sont extraits dans un sous-processus avec délai et limites de ressources. Les PDF scannés sans texte, chiffrés, illisibles ou trop longs donnent un avertissement de couverture. Le moteur n’est pas un analyseur universel de rapports PDF. Il n’exécute pas de reconnaissance de texte par OCR.

**Les rapports manquants ne sont pas encore surveillés.** Il faut d’abord définir un calendrier et une marge de retard par tâche. Mettre `expected_reports.enabled` à `true` est refusé pour éviter de laisser croire à une surveillance non implémentée. Les envois automatiques restent désactivés. Un bilan peut être envoyé ponctuellement avec la commande ci-dessous.

## Envoyer ponctuellement le bilan par email

Depuis la console Portainer du conteneur, après une collecte réussie :

```sh
python -m logtriage.report --to destinataire@example.com --smtp-host smtp.example.com --smtp-port 465 --use-imap-credentials
```

Cette commande utilise explicitement l’identifiant et le mot de passe IMAP déjà configurés. Utilise-la seulement si le serveur SMTP accepte ces mêmes identifiants. Pour un compte différent, configure `SMTP_USER` et `SMTP_PASSWORD` (ou `SMTP_PASSWORD_FILE`) et retire `--use-imap-credentials`. `--from` permet de préciser l’adresse d’expédition si l’identifiant n’est pas une adresse email complète. La connexion SMTP utilise TLS avec vérification du certificat.

Ajoute `--preview` pour afficher le contenu sans connexion SMTP. Le rapport utilise les résultats réels déjà disponibles, sans relancer le collecteur ni modifier la boîte. Un import encore partiel ou un bilan ancien est signalé. Une confirmation d’acceptation SMTP est conservée dans `/data/last-report-send.json` ; elle ne prouve pas à elle seule la livraison dans la boîte du destinataire. Aucun envoi quotidien n’est programmé.

Les paramètres `report.window_hours`, `report.max_groups`, `report.disk_warning_percent` et `report.memory_warning_percent` sont définis dans `config/rules.json`. Au-delà du nombre maximal de groupes, un compteur annonce les autres points disponibles dans les exports.

## État du service

```sh
docker compose -f compose.local.yaml ps
docker compose -f compose.local.yaml exec triage cat /data/status.json
```

Le contrôle de santé vérifie qu’un cycle récent s’est terminé correctement. Les identifiants invalides, erreurs TLS/IMAP et messages qui n’ont pas pu être récupérés apparaissent comme erreurs ou état dégradé. Un email dont le format n’est pas reconnu est tout de même analysé et reste visible dans `a_verifier`. Les messages dépassant `MAX_MESSAGE_BYTES` sont signalés dans `status.json`, sans téléchargement du corps, puis réessayés ; une rotation empêche qu’ils bloquent les messages suivants.

Pour une seule collecte et l’export correspondant :

```sh
docker compose -f compose.local.yaml stop triage
docker compose -f compose.local.yaml run --rm triage once
```

Évite de lancer deux collecteurs simultanés sur le même volume. `docker compose -f compose.local.yaml down` conserve le volume ; sauvegarde-le si tu veux conserver ton historique. N’ajoute pas `--volumes` à cette commande sauf si tu veux effacer les résultats locaux.

## Essai hors connexion avec des fichiers .eml

Ce mode ne demande aucun accès IMAP et peut s’exécuter sans réseau. Exemple si le projet et `emails_log` sont côte à côte :

```sh
docker build -t imap-log-triage:local .
docker run --rm --network none --read-only --tmpfs /tmp \
  -v triage-sample:/data \
  -v "$(pwd)/../emails_log:/samples:ro" \
  imap-log-triage:local import-eml /samples
docker run --rm --network none --read-only --tmpfs /tmp \
  -v triage-sample:/data \
  --entrypoint cat imap-log-triage:local /data/exports/bilan.txt
```

Le volume `triage-sample` est distinct de `triage-data` utilisé pour IMAP. L’import est limité aux `.eml` directement présents dans le dossier indiqué. Réimporter les mêmes fichiers ne les recompte pas.

## Vérification locale sans Docker

Avec Python 3.13 ou plus récent et les dépendances de `requirements.txt` :

```sh
python -m unittest discover -s tests -v
DATA_DIR=./data python -m logtriage import-eml ../emails_log
```

Pour ajouter le contrôle des dix exemples privés et de leur classement de référence :

```sh
SAMPLE_EMAIL_DIR=../emails_log python -m unittest discover -s tests -v
```

Les tests couvrent le protocole IMAP en lecture seule, les identifiants persistants, la réimportation, les cas ambigus, les erreurs dans une variante HTML, les PDF illisibles et les rétablissements chronologiques. Les exemples privés et leurs PDF ne sont pas inclus dans l’image ni dans l’archive de livraison.

## Références techniques

- [Client IMAP Python : select readonly et récupération des messages](https://docs.python.org/3/library/imaplib.html)
- [Extraction de texte PDF avec pypdf](https://pypdf.readthedocs.io/en/stable/user/extract-text.html)
- [Image Python officielle](https://hub.docker.com/_/python)
- [Stacks Portainer et variables d’environnement](https://docs.portainer.io/user/docker/stacks/add)
- [Déclaration des secrets Compose](https://docs.docker.com/reference/compose-file/secrets/)
