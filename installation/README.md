# 🛡️ SIEM AFRICA — Module 1 : IDS & SIEM

> Module 1 du projet SIEM Africa : Système de détection d'intrusion (Snort) et gestionnaire SIEM (Wazuh) pour PME africaines.

---

## 📖 Présentation

Le **Module 1** constitue la couche **capteur** de SIEM Africa. Il assure :
- La détection d'intrusions réseau via **Snort IDS** (mode passif)
- La gestion SIEM centralisée via **Wazuh Manager**
- Optionnellement, une interface web via **Wazuh Dashboard** (mode full)

C'est le **premier module à installer**. Il crée l'infrastructure de base (groupe, users, fichier d'état) que les autres modules utiliseront.

---

## 🎯 Modes d'installation disponibles

### Mode **LITE** (léger)
- **Composants** : Snort IDS + Wazuh Manager
- **Pas d'interface web Wazuh**
- **Prérequis** : 4 GB RAM, 50 GB disque
- **Cible** : PME avec matériel limité, serveurs mono-usage
- **Avantage** : Faible consommation ressources
- **Note** : Les alertes seront visualisées via le Module 4 (Dashboard Django)

### Mode **FULL** (complet)
- **Composants** : Snort IDS + Wazuh Manager + Indexer + Dashboard
- **Interface web Wazuh complète** (analyse avancée)
- **Prérequis** : 8 GB RAM, 50 GB disque
- **Cible** : PME moyennes à grandes, analystes sécurité
- **Avantage** : Double interface (Wazuh Dashboard pour analystes, Django pour gestionnaires)

---

## 💻 Systèmes supportés

| OS | Version | Statut |
|----|---------|--------|
| Ubuntu | 22.04 LTS (Jammy) | ✅ Supporté, testé |
| Ubuntu | 24.04 LTS (Noble) | ✅ Supporté, testé |
| Debian | 11 (Bullseye) | ✅ Supporté (compatibilité théorique) |
| Debian | 12 (Bookworm) | ✅ Supporté (compatibilité théorique) |

**Architecture** : x86_64 uniquement (ARM en perspectives V2.1).

---

## 🚀 Utilisation rapide

### Option 1 : Installation guidée (recommandée pour débutants)
```bash
sudo ./install.sh
```
Un menu interactif vous demandera le mode à installer.

### Option 2 : Installation directe Mode LITE
```bash
sudo ./install-lite.sh
```

### Option 3 : Installation directe Mode FULL
```bash
sudo ./install-full.sh
```

### Désinstallation
```bash
sudo ./uninstall.sh
```

### Réparation (en cas de problème)
```bash
sudo ./repair.sh
```

---

## 📋 Prérequis

Le script vérifie automatiquement avant installation :

- [ ] Droits root (`sudo`)
- [ ] Système supporté (Ubuntu 22.04/24.04 ou Debian 11/12)
- [ ] Connexion internet active
- [ ] RAM disponible (4 GB lite / 8 GB full)
- [ ] Espace disque disponible (50 GB minimum)
- [ ] Interface réseau détectée
- [ ] Ports requis disponibles
- [ ] Aucune installation corrompue préexistante

**Si un prérequis échoue**, l'installation s'arrête avec un message d'erreur et une solution proposée.

---

## 🏗️ Architecture

```
📁 module-1-ids-siem/
│
├── 📄 install.sh              → Script principal (menu interactif)
├── 📄 install-lite.sh         → Installation directe Mode LITE
├── 📄 install-full.sh         → Installation directe Mode FULL
├── 📄 uninstall.sh            → Désinstallation propre
├── 📄 repair.sh               → Réparation d'installation
│
├── 📁 core/                   → Fonctions réutilisables
│   ├── logging.sh             → Logs formatés (INFO, SUCCESS, WARN, ERROR)
│   ├── langue.sh              → Support FR/EN
│   ├── os-detect.sh           → Détection Ubuntu/Debian
│   ├── prerequis.sh           → Vérifications système
│   ├── users.sh               → Gestion groupe siem-africa + users
│   └── state.sh               → Fichier d'état YAML
│
├── 📁 modules/                → Étapes d'installation
│   ├── 01-system-prep.sh      → Préparation système
│   ├── 02-snort.sh            → Installation Snort 2.9
│   ├── 03-wazuh-manager.sh    → Installation Wazuh Manager 4.14
│   ├── 04-wazuh-indexer.sh    → (Mode FULL) Wazuh Indexer
│   ├── 05-wazuh-dashboard.sh  → (Mode FULL) Wazuh Dashboard
│   ├── 06-integration.sh      → Intégration Snort ↔ Wazuh
│   └── 07-state-file.sh       → Génération fichier d'état
│
├── 📁 config/                 → Templates de configuration
│   ├── snort/
│   │   ├── snort.conf.template
│   │   └── local.rules
│   ├── wazuh/
│   │   └── ossec.conf.template
│   └── systemd/
│       └── siem-africa-snort.service
│
└── 📁 tests/                  → Tests de validation
    ├── test-snort.sh
    ├── test-wazuh.sh
    └── test-integration.sh
```

---

## 🔐 Sécurité

### Principe du moindre privilège
Chaque composant fonctionne avec son propre utilisateur système :
- `siem-ids` : Snort + Wazuh Manager (Module 1)
- `siem-db` : Base de données (Module 2)
- `siem-agent` : Agent Python (Module 3)
- `siem-web` : Dashboard Django (Module 4)

Tous ces utilisateurs appartiennent au groupe **`siem-africa`** qui gère les accès partagés.

### Fichier d'état protégé
`/etc/siem-africa/siem-africa.state.yaml` (permissions `640`, propriétaire `root:siem-admin`)

### Mots de passe
Stockés dans `/etc/siem-africa/secrets/` avec permissions `600` (lecture root uniquement).

---

## 📝 Fichiers générés par le script

Après installation réussie, les fichiers suivants sont créés :

| Fichier | Rôle |
|---------|------|
| `/etc/siem-africa/siem-africa.state.yaml` | État complet de l'installation (YAML) |
| `/etc/siem-africa/RESUME.txt` | Résumé lisible (commandes, credentials) |
| `/etc/siem-africa/secrets/wazuh-admin.pwd` | Mot de passe admin Wazuh (mode FULL) |
| `/var/log/siem-africa/install.log` | Log complet de l'installation |
| `/var/log/siem-africa/` | Logs des modules |
| `/var/lib/siem-africa/` | Données partagées (DB future) |
| `/opt/siem-africa/` | Code des modules |

---

## 🧪 Tests de validation

Après installation, des tests automatiques vérifient :

```bash
# Tests individuels
sudo ./tests/test-snort.sh
sudo ./tests/test-wazuh.sh
sudo ./tests/test-integration.sh

# Ou via le script principal
sudo systemctl status snort
sudo systemctl status wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

---

## 📚 Documentation complémentaire

- **INSTALL.md** : Guide d'installation détaillé étape par étape
- **FAQ-JURY.md** : Questions probables de soutenance et réponses types
- **Rapport académique** : Chapitre "Implémentation — Module 1"

---

## 🛠️ Dépannage rapide

| Problème | Solution |
|----------|----------|
| "Port 1514 déjà utilisé" | `sudo ./uninstall.sh` puis réinstaller |
| "Installation corrompue détectée" | `sudo ./repair.sh` |
| "Snort ne démarre pas" | Vérifier interface réseau dans `/etc/siem-africa/siem-africa.state.yaml` |
| "Wazuh Dashboard inaccessible" | Vérifier firewall : `sudo ufw status` |

---

## 📧 Contact & Contribution

**Projet** : SIEM Africa v2.0
**Repository** : [github.com/africa-siem/africa-siem](https://github.com/africa-siem/africa-siem)
**Auteur** : Gaetan — IUT de Douala, Cameroun
**Licence** : MIT

---

*Module développé dans le cadre d'un mémoire de fin d'études de licence, IUT de Douala, promotion 2025-2026.*
