# 🎓 FAQ Jury — Questions probables en soutenance

> Questions qui peuvent être posées par le jury lors de la soutenance du mémoire, avec réponses types à adapter avec tes propres mots.

---

## 📌 Utilisation de ce document

Ce fichier liste les **questions probables** du jury sur le Module 1 et des **réponses modèles**.

**Règles importantes** :
1. **Ne récite pas les réponses** → reformule avec tes mots
2. **Montre que tu comprends** les concepts, pas juste le code
3. **Reste humble** : si tu ne sais pas, dis-le et propose une piste de réflexion
4. **Prépare des exemples concrets** pour illustrer

---

## 🏗️ PARTIE 1 — Architecture & Choix techniques

### Q1.1 : Qu'est-ce qu'un SIEM ?

**Réponse** :
> Un SIEM (*Security Information and Event Management*) est une solution qui **centralise** et **analyse** en temps réel les événements de sécurité provenant de multiples sources (réseaux, serveurs, applications). Il permet :
> - La **détection** d'incidents de sécurité (intrusions, comportements anormaux)
> - La **corrélation** d'événements apparemment isolés
> - La **réponse** rapide aux incidents
> - La **conformité** réglementaire (audits)
>
> Un SIEM repose sur 3 piliers : **collecte**, **analyse**, et **action**.

---

### Q1.2 : Pourquoi avoir choisi Snort et Wazuh ?

**Réponse** :
> **Snort** est un IDS open source mature (30 ans d'existence), maintenu par Cisco Talos. Ses règles de détection sont reconnues par l'industrie comme référence. Il est performant, léger, et dispose d'une base de règles communautaires très riche.
>
> **Wazuh** est un SIEM open source basé sur OSSEC, utilisé par des entreprises du Fortune 500. Il offre :
> - La **gestion d'agents** sur les postes de travail
> - L'**intégration native** avec Snort
> - Des **frameworks de conformité** (PCI-DSS, HIPAA, NIST)
> - Une interface web complète (mode FULL)
>
> Cette combinaison offre une solution **100% open source**, **professionnelle**, et **adaptée aux PME** qui ne peuvent pas investir dans des solutions propriétaires comme Splunk (50 000€+/an) ou QRadar.

---

### Q1.3 : Pourquoi supporter Ubuntu ET Debian ?

**Réponse** :
> Nous avons choisi de supporter les deux distributions Linux **les plus déployées en entreprise** :
>
> - **Ubuntu** : très répandu dans les PME modernes, les startups, et les environnements cloud (DigitalOcean, AWS).
> - **Debian** : historiquement choisi par les institutions critiques (universités, ministères, ONG) pour sa **gouvernance communautaire** et sa **stabilité supérieure**.
>
> En Afrique, notamment au Cameroun et au Sénégal, Debian est souvent privilégié par les structures publiques pour des raisons de souveraineté (projet communautaire sans entreprise commerciale derrière, contrairement à Ubuntu/Canonical).
>
> Supporter les deux permet à SIEM Africa de s'adapter à l'écosystème réel, sans forcer les entreprises à changer leur infrastructure.

---

### Q1.4 : Pourquoi deux modes d'installation (LITE et FULL) ?

**Réponse** :
> Cette dualité répond à une **réalité économique et technique africaine** : toutes les PME n'ont pas les mêmes ressources matérielles.
>
> - **Mode LITE** (4 GB RAM) : pour les petites PME disposant de vieux matériel recyclé, de Raspberry Pi, ou de mini-PC. Il offre l'essentiel : détection d'intrusion et collecte SIEM. La visualisation se fait via notre dashboard Django (Module 4), plus léger que le Wazuh Dashboard natif.
>
> - **Mode FULL** (8 GB RAM) : pour les PME moyennes à grandes disposant d'un serveur dédié. Il ajoute l'interface web Wazuh native, utile aux **analystes sécurité** qui préfèrent les outils professionnels standards.
>
> Cette flexibilité est un **différenciateur** vs les SIEM commerciaux qui imposent une configuration rigide.

---

### Q1.5 : Pourquoi Snort 2.9 et pas Snort 3 ?

**Réponse** :
> Snort 3 est plus récent mais présente encore quelques instabilités et sa documentation est moins mature. Snort 2.9 offre :
> - Une **stabilité éprouvée** en production
> - Une **documentation exhaustive** (15+ ans de retours d'expérience)
> - Une **compatibilité totale** avec les règles communautaires
> - Un **support Wazuh natif**
>
> Snort 3 pourrait être intégré dans une future version 2.1, une fois l'écosystème stabilisé.

---

### Q1.6 : Pourquoi Snort en mode IDS passif et pas IPS actif ?

**Réponse** :
> Un **IDS passif** se contente de **détecter et alerter** sans bloquer. Un **IPS actif** (*inline*) **bloque activement** le trafic suspect.
>
> Nous avons choisi l'IDS passif pour plusieurs raisons :
> 1. **Moins de risque** : un IPS mal configuré peut bloquer du trafic légitime et paralyser l'entreprise
> 2. **Architecture modulaire** : le blocage est délégué au Module 3 (Agent Python) qui applique des règles **corrélées** via iptables, après validation croisée
> 3. **Approche incrémentale** : une PME qui débute avec un SIEM doit d'abord **comprendre** son trafic avant de commencer à bloquer
>
> Cette séparation détection/action suit le principe de **défense en profondeur**.

---

## 🔐 PARTIE 2 — Sécurité

### Q2.1 : Comment sécurisez-vous le SIEM lui-même ?

**Réponse** :
> Un SIEM mal sécurisé est **pire qu'aucun SIEM** car il devient une cible prioritaire. Nous appliquons plusieurs principes :
>
> 1. **Moindre privilège** : chaque module a son utilisateur système dédié (`siem-ids`, `siem-db`, etc.) avec des permissions limitées
> 2. **Groupe partagé** (`siem-africa`) pour les accès contrôlés aux ressources communes
> 3. **Shell `/bin/false`** pour tous les users service → impossible de se connecter directement
> 4. **Permissions strictes** sur les fichiers sensibles (`640` pour le state file, `600` pour les secrets)
> 5. **Mots de passe** stockés dans des fichiers séparés (`/etc/siem-africa/secrets/`)
> 6. **Pas de `set -e`** dans les scripts bash → évite les échecs silencieux
> 7. **Détection d'installation corrompue** au démarrage pour éviter les états incohérents

---

### Q2.2 : Comment gérez-vous les mots de passe ?

**Réponse** :
> Les mots de passe ne sont **jamais** :
> - Écrits en dur dans le code
> - Commités sur GitHub
> - Affichés dans les logs
>
> Ils sont :
> - **Générés aléatoirement** lors de l'installation (pas de mots de passe par défaut)
> - Stockés dans `/etc/siem-africa/secrets/` avec permissions `600`
> - Référencés dans le fichier d'état **par chemin** et non par valeur
> - Affichés **une seule fois** à la fin de l'installation (dans le RESUME.txt), avec consigne de changement immédiat

---

### Q2.3 : Que se passe-t-il si un attaquant compromet le SIEM ?

**Réponse** :
> C'est un risque majeur que nous adressons par plusieurs contre-mesures :
>
> 1. **Logs horodatés** dans plusieurs emplacements (`/var/log/siem-africa/`, `/var/ossec/logs/`, `/var/log/snort/`)
> 2. **Principe du moindre privilège** : même compromis, un module ne peut pas accéder aux autres
> 3. **Possibilité de transfert de logs** vers un serveur distant (roadmap V2.1)
> 4. **Audit trail** : toutes les actions administratives loguées
>
> **Limitation connue** : pas encore de détection d'intégrité (signature des fichiers de règles). C'est une **amélioration prévue** en V2.1.

---

## ⚙️ PARTIE 3 — Implémentation technique

### Q3.1 : Pourquoi un dossier `core/` ?

**Réponse** :
> Le dossier `core/` contient les **fonctions réutilisables** communes à tous les scripts d'installation. Cette architecture applique le principe **DRY** (*Don't Repeat Yourself*) :
>
> - Le code commun est écrit **une seule fois** dans `core/`
> - Il est **appelé** (via la commande `source`) depuis chaque script qui en a besoin
>
> **Avantages** :
> - **Maintenance** : une correction se propage automatiquement
> - **Cohérence** : tous les scripts utilisent la même logique
> - **Lisibilité** : les scripts d'installation restent courts et clairs
>
> C'est une pratique standard dans les projets Ansible, Terraform, et tous les outils DevOps modernes.

---

### Q3.2 : Qu'est-ce que le "fichier d'état" ?

**Réponse** :
> Le fichier d'état (`/etc/siem-africa/siem-africa.state.yaml`) est une **base de connaissances centralisée** qui contient :
> - Métadonnées de l'installation (date, version, mode)
> - Configuration système (OS, RAM, interfaces)
> - Modules installés (version, chemins, ports)
> - Commandes utiles (vérification, redémarrage)
> - Références vers les mots de passe
>
> **Pourquoi c'est utile** :
> - **Debugging** : en cas de problème, un seul fichier à consulter
> - **Maintenance** : un nouveau technicien comprend le système en 5 minutes
> - **Évolution** : les modules suivants (2, 3, 4) mettent à jour ce fichier au fur et à mesure
>
> Le format **YAML** a été choisi car il est **lisible par un humain** ET **parsable par des scripts**, contrairement au JSON (plus technique) ou au texte brut (non structuré).

---

### Q3.3 : Pourquoi lire `alerts.json` directement et pas l'API Wazuh ?

**Réponse** :
> C'est un **choix pragmatique** basé sur notre expérience V1 :
>
> **Contexte** : les endpoints `/alerts` et `/security/events` ne sont pas disponibles dans les versions stables actuelles de l'API Wazuh. L'API est plutôt orientée **gestion des agents** (enrôlement, état) que récupération d'alertes.
>
> **Solution choisie** : lire directement le fichier `alerts.json` écrit par Wazuh. C'est :
> - **Simple** (pas de gestion de tokens, d'authentification)
> - **Performant** (pas de latence réseau en local)
> - **Fiable** (pas de surprise de version API)
>
> **Limitations** (que nous assumons) :
> - Pas de filtrage côté source
> - Gestion manuelle de la rotation de logs
> - Pas de push notifications
>
> **Amélioration future** (V2.1) : utiliser **Filebeat** + **Wazuh Indexer** (OpenSearch) qui est la stack officielle pour l'ingestion. Cela permettrait requêtes structurées et meilleure scalabilité.

---

### Q3.4 : Pourquoi ne pas utiliser `set -e` dans les scripts bash ?

**Réponse** :
> `set -e` arrête un script bash au premier échec de commande. En théorie c'est bien, en pratique c'est **piégeux** :
>
> 1. Il **cache les erreurs** : le script s'arrête sans message clair
> 2. Il réagit à des **faux positifs** (ex: `grep` qui ne trouve rien retourne 1 = "erreur")
> 3. Il **complique le debug** : impossible de savoir où ça a planté sans logs détaillés
> 4. Il **empêche la récupération** d'erreurs non-critiques
>
> Notre approche :
> - Fonction `check_error()` custom qui log **explicitement** chaque erreur
> - Arrêt **maîtrisé** avec message clair et solution proposée
> - Logs horodatés pour post-mortem
>
> Cette leçon nous a coûté des heures de debug en V1. La V2 assume une gestion d'erreurs **explicite et traçable**.

---

### Q3.5 : Pourquoi les PID dans `/var/log/` et pas `/var/run/` ?

**Réponse** :
> `/var/run/` est un **tmpfs** (système de fichiers en mémoire) sur la plupart des distributions modernes. Il est **vidé à chaque reboot**.
>
> Problème : certains services créent leur PID file au démarrage et s'attendent à le retrouver plus tard. Si `/var/run/` est éphémère et que le service redémarre, on peut se retrouver avec des PID files fantômes ou manquants.
>
> `/var/log/` est **persistant** et logiquement associé aux logs/états des services. C'est un choix pragmatique pour éviter les bugs de démarrage observés en V1.

---

## 🌍 PARTIE 4 — Adaptation contexte africain

### Q4.1 : En quoi SIEM Africa est-il adapté aux PME africaines ?

**Réponse** :
> L'adaptation est à plusieurs niveaux :
>
> 1. **Matériel** : mode LITE pour PC recyclés, support ARM en roadmap (Raspberry Pi ~50€)
> 2. **Connectivité** : architecture **on-premise** → fonctionne même sans internet permanent. Mode offline-first en roadmap.
> 3. **Coût** : 100% open source, pas de licence, paiement mobile (Mobile Money) pour le support
> 4. **Langues** : FR/EN natif, AR/PT en roadmap
> 5. **Conformité** : support des cadres africains (Convention de Malabo, lois nationales)
> 6. **Souveraineté** : données restent en Afrique (pas de cloud US/EU)
> 7. **Menaces spécifiques** : signatures pour fraude Mobile Money, BEC, ransomwares régionaux (roadmap V2.1)

---

### Q4.2 : Pourquoi le nom "SIEM Africa" et pas un nom neutre ?

**Réponse** :
> Le nom reflète une **ambition** et un **positionnement** :
>
> - **Ambition** : devenir LA solution SIEM open source de référence pour le continent africain
> - **Positionnement** : contrairement aux solutions européennes/américaines, nous concevons **depuis et pour** l'Afrique, avec ses réalités techniques et économiques
>
> Ce n'est pas un argument marketing vide : chaque choix technique (LITE mode, on-premise obligatoire, paiement mobile, menaces locales) découle de cette vision.

---

## 🎯 PARTIE 5 — Questions pièges

### Q5.1 : Si votre SIEM tombe en panne, que se passe-t-il ?

**Réponse** :
> C'est une question critique. Actuellement :
>
> 1. Les services Snort et Wazuh ont un **restart automatique** via systemd
> 2. Les logs sont **persistants** (pas perdus en cas de crash)
> 3. Un script de réparation (`repair.sh`) permet une restauration rapide
>
> **Limitations assumées** (V2.0) :
> - Pas de haute disponibilité (pas de cluster)
> - Pas de monitoring externe (watchdog)
>
> **Roadmap V2.1** :
> - Watchdog externe (heartbeat)
> - Backup automatique du fichier d'état
> - Support cluster Wazuh (2+ nodes)
>
> Pour une PME, le risque est **acceptable** car la perte du SIEM signifie une dégradation de la visibilité, pas un arrêt des opérations métier.

---

### Q5.2 : Quelle est la différence avec un Wazuh standalone ?

**Réponse** :
> Wazuh seul est une **brique** de SIEM. SIEM Africa est une **solution complète** qui orchestre plusieurs briques :
>
> | Aspect | Wazuh seul | SIEM Africa |
> |--------|------------|-------------|
> | Installation | Manuelle, complexe | Script automatisé 1 commande |
> | IDS réseau | Pas intégré | Snort intégré natif |
> | Base de données | OpenSearch lourd | SQLite léger (choix PME) |
> | Dashboard | Kibana complexe | Django simplifié + Wazuh au choix |
> | Agent intelligent | Basique | Agent Python avec corrélation + honeypots |
> | Adaptation locale | Aucune | FR/EN, contexte africain, Mobile Money |
> | Coût d'entrée | Expertise requise | Accessible PME |
>
> **SIEM Africa = Wazuh + Snort + orchestration + simplification + localisation**.

---

### Q5.3 : Votre projet est un mémoire de licence. Est-il prêt pour la production ?

**Réponse** :
> **Honnêtement**, non, pas encore. Et c'est normal.
>
> **Ce qui est prêt** :
> - Architecture saine et modulaire
> - Choix techniques solides et justifiés
> - Installation automatisée fiable
> - Détection fonctionnelle des menaces classiques
>
> **Ce qui manque pour la production** :
> - Tests de charge (volumes réels)
> - Audit de sécurité externe
> - Support multi-tenants
> - Documentation utilisateur complète
> - Formation du personnel utilisateur
> - Contrats de support
>
> Le projet est au stade **MVP (Minimum Viable Product)**. Il démontre **la faisabilité** et pose les **fondations solides** pour une évolution ultérieure vers un produit commercial.
>
> Cette honnêteté est préférable à des affirmations commerciales non fondées.

---

### Q5.4 : Pourquoi n'avez-vous pas utilisé une solution existante comme ELK ?

**Réponse** :
> ELK (Elasticsearch + Logstash + Kibana) est excellent mais :
>
> 1. **Très gourmand** : nécessite 16+ GB RAM pour fonctionner correctement (incompatible avec les PME africaines)
> 2. **Courbe d'apprentissage raide** : configuration complexe
> 3. **Licence ambiguë** : Elastic a changé sa licence en 2021, créant des incertitudes juridiques (fork OpenSearch d'AWS)
> 4. **Pas de SIEM natif** : il faut construire toute la logique de corrélation
>
> Wazuh offre :
> - Un **vrai SIEM** complet out-of-the-box
> - Des **ressources raisonnables** (mode lite 4 GB RAM)
> - Une **licence claire** (Apache 2.0)
> - Une **intégration native** avec Snort
>
> D'ailleurs, Wazuh utilise lui-même OpenSearch (fork ELK) en interne dans le mode FULL. Nous bénéficions des **avantages** d'ELK sans en subir la **complexité**.

---

## 💪 Derniers conseils pour la soutenance

### 1. Connaître les chiffres clés
- **380 signatures MITRE** (Module 2)
- **14 tables** SQLite
- **Temps d'installation** : ~10 minutes (LITE), ~15 minutes (FULL)
- **Versions** : Wazuh 4.14, Snort 2.9, Ubuntu 22.04/24.04, Debian 11/12

### 2. Préparer une démonstration
- Une **attaque simulée** (nmap, hydra, hping3) qui déclenche une alerte
- Le **workflow complet** : attaque → Snort détecte → Wazuh enregistre → Dashboard affiche

### 3. Avoir un plan B
Si une démo plante, avoir :
- **Des captures d'écran** des alertes qui ont fonctionné
- **Des logs** réels
- Une **vidéo pré-enregistrée** de la démo en backup

### 4. Attitude
- **Humble** sur les limites (montre que tu les connais)
- **Enthousiaste** sur la vision (montre que tu y crois)
- **Précis** sur les choix techniques (montre que tu maîtrises)

### 5. Savoir dire "je ne sais pas"
> *"C'est une excellente question à laquelle je n'ai pas de réponse immédiate. Ma première intuition serait [X], mais je préfère approfondir avant de m'engager."*

**Cette phrase vaut de l'or**. Un jury respecte l'honnêteté intellectuelle.

---

*Bon courage pour ta soutenance Gaetan ! 💪*

*FAQ rédigée pour SIEM Africa v2.0 — IUT de Douala, 2026*
