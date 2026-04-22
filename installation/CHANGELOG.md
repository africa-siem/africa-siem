# 📝 CHANGELOG — Module 1 SIEM Africa

> Journal des modifications du Module 1 (IDS & SIEM).

---

## [2.0.0] — 2026-04-22 (REWRITE COMPLET)

### 🎉 Nouvelle version majeure

Refonte complète du Module 1 basée sur les retours d'expérience de la V1.
Architecture repartie de zéro, plus propre et maintenable.

### ✨ Ajouts

#### Scripts d'installation
- **3 scripts d'installation** : `install.sh` (menu), `install-lite.sh`, `install-full.sh`
- Sélection de langue (FR/EN) au démarrage
- Détection automatique de l'OS (Ubuntu/Debian)
- Vérifications bloquantes des prérequis
- Mode interactif avec confirmations

#### Architecture modulaire
- Dossier `core/` avec fonctions réutilisables (DRY)
  - `logging.sh` : logs uniformes avec couleurs
  - `langue.sh` : i18n FR/EN
  - `os-detect.sh` : compatibilité multi-distributions
  - `prerequis.sh` : vérifications système
  - `users.sh` : gestion groupe `siem-africa`
  - `state.sh` : fichier d'état YAML
- Dossier `modules/` : étapes d'installation découpées
- Dossier `config/` : templates de configuration
- Dossier `scripts/` : outils de maintenance
- Dossier `tests/` : validation automatique

#### Sécurité
- Groupe système `siem-africa` partagé entre modules
- Utilisateurs service avec shell `/bin/false`
- Permissions strictes sur les fichiers sensibles
- Secrets dans `/etc/siem-africa/secrets/` (chmod 600)
- Pas de passwords hardcodés

#### Fichier d'état centralisé
- `/etc/siem-africa/siem-africa.state.yaml` (format structuré)
- `/etc/siem-africa/RESUME.txt` (format lisible)
- Mise à jour automatique par les modules

#### Community Rules
- Téléchargement automatique Emerging Threats Open (gratuit)
- Profil PME : ~8-10k règles activées (équilibré)
- Mise à jour automatique hebdomadaire (cron lundi 3h)
- Script manuel `scripts/update-rules.sh`

#### Compatibilité
- Ubuntu 22.04 LTS (Jammy)
- Ubuntu 24.04 LTS (Noble)
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)

#### Documentation
- `README.md` : présentation complète
- `INSTALL.md` : guide d'installation détaillé
- `QUICK-START.md` : démarrage rapide
- `FAQ-JURY.md` : préparation soutenance (20+ Q&R)
- `CHANGELOG.md` : historique (ce fichier)
- Commentaires extensifs dans tous les scripts

#### Tests
- `tests/test-snort.sh` : validation Snort (8 tests)
- `tests/test-wazuh.sh` : validation Wazuh (8 tests)
- `tests/test-integration.sh` : workflow complet

#### Maintenance
- `uninstall.sh` : désinstallation propre (avec option `--purge`)
- `repair.sh` : réparation automatique non destructive

### 🔧 Hard-won fixes intégrés depuis la V1

- ❌ Suppression de `set -e` (causait des échecs silencieux)
- ✅ PID Snort dans `/var/log/` (pas `/var/run/` éphémère)
- ✅ `log_format = snort-fast` pour Wazuh (pas `snort` seul)
- ✅ Pas de `ProtectSystem=strict` dans systemd (causait CHDIR error 200)
- ✅ Pas de `PrivateTmp=yes` (bloquait accès logs)
- ✅ `chmod 664` sur fichiers partagés + groupe `siem-africa`
- ✅ Détection install corrompue via `dpkg` au démarrage
- ✅ Lecture directe de `alerts.json` (pas l'API Wazuh qui n'existe pas)

### 🎯 Décisions architecturales

- **Snort + Wazuh** avec Community Rules uniquement
- **Pas de règles custom hardcodées** (déplacées vers Module 2)
- **Mapping MITRE ATT&CK** centralisé dans Module 2 (base de données)
- **Mode LITE / FULL** pour s'adapter aux ressources PME
- **Architecture on-premise** (souveraineté des données)

### 📊 Métriques

- **26 fichiers** au total dans le module
- **~3500 lignes** de code bash
- **~1500 lignes** de documentation
- **Temps d'installation** : ~10 min (LITE), ~15 min (FULL)
- **Couverture** : ~10 000 règles de détection actives

---

## [1.0.0] — 2024 (Version archivée)

Première version du projet SIEM Africa.

### 🎓 Contexte
- Projet initial étudiant (IUT Douala)
- Évolution progressive : script d'installation → SIEM complet
- Base d'apprentissage pour la V2

### 🔄 Limites identifiées (corrigées en V2)
- Utilisation de `set -e` (échecs silencieux)
- API Wazuh endpoints inexistants
- PID dans `/var/run/` (perdus au reboot)
- Permissions SQLite incohérentes
- `ProtectSystem=strict` causant CHDIR error
- Scripts monolithiques difficiles à maintenir

### 📦 Version archivée
- Repository : `github.com/luciesys/SIEM-AFRICA` (archivé)
- Tag : `v1-final`

---

## Roadmap — Versions futures

### [2.1.0] — Prévue Q3 2026

#### À venir
- 🔄 Module 2 : Base de données SQLite + 380 signatures MITRE ATT&CK
- 🔄 Module 3 : Agent Python (honeypots, corrélation, iptables)
- 🔄 Module 4 : Dashboard Django
- 🔍 Tests unitaires Python (pytest)
- 📦 Packages `.deb` pour installation simplifiée
- 🔐 Chiffrement au repos (SQLCipher)

### [2.2.0] — Prévue Q4 2026

#### À venir
- 🤖 Module ML (Random Forest + SHAP explicabilité)
- 📱 Module 5 : PWA mobile
- 🌍 i18n étendue : Arabe (RTL), Portugais, Swahili
- 🏦 Signatures spécifiques Mobile Money (MTN, Orange, Moov)
- 📊 Rapports de conformité (Convention 108+, lois nationales)

### [3.0.0] — 2027

#### À venir
- 🏗️ Architecture multi-tenants (SaaS pour plusieurs PME)
- ☁️ Déploiement cloud-native (Kubernetes)
- 🔗 Intégration CERT nationaux africains
- 🧠 Threat Intelligence Feed africain
- 📱 Applications natives iOS/Android

---

## Format du Changelog

Ce fichier suit les conventions de [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

Types de changements :
- `✨ Ajouts` : nouvelles fonctionnalités
- `🔄 Modifications` : changements dans les fonctionnalités existantes
- `❌ Dépréciations` : fonctionnalités bientôt supprimées
- `🗑️ Suppressions` : fonctionnalités supprimées
- `🐛 Corrections` : bugs corrigés
- `🔒 Sécurité` : vulnérabilités corrigées

---

*SIEM Africa — IUT de Douala, Cameroun — 2026*
