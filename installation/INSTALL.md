# 📥 Guide d'installation — Module 1

> Guide complet étape par étape pour installer le Module 1 de SIEM Africa.

---

## 🎯 Avant de commencer

### Vérifications préalables

Avant de lancer l'installation, assure-toi que :

1. **Tu as un accès root** (via `sudo`)
2. **Ta VM dispose des ressources nécessaires** :
   - Mode LITE : 4 GB RAM minimum, 50 GB disque
   - Mode FULL : 8 GB RAM minimum, 50 GB disque
3. **Une connexion internet est active**
4. **Le système est Ubuntu 22.04/24.04 ou Debian 11/12**

### Commandes de vérification rapide

```bash
# Vérifier la version du système
cat /etc/os-release

# Vérifier la RAM disponible
free -h

# Vérifier l'espace disque
df -h /

# Vérifier la connexion internet
ping -c 3 8.8.8.8

# Vérifier l'interface réseau active
ip a | grep "state UP"
```

---

## 📦 Étape 1 : Récupérer le code

### Option A : Cloner depuis GitHub

```bash
cd /opt
sudo git clone https://github.com/africa-siem/africa-siem.git
cd africa-siem/module-1-ids-siem
```

### Option B : Copier depuis un support externe (USB, SCP)

```bash
# Si copié dans /tmp
sudo cp -r /tmp/module-1-ids-siem /opt/
cd /opt/module-1-ids-siem
```

### Donner les permissions d'exécution

```bash
sudo chmod +x install.sh install-lite.sh install-full.sh uninstall.sh repair.sh
sudo chmod +x core/*.sh modules/*.sh tests/*.sh
```

---

## 🚀 Étape 2 : Lancer l'installation

### Choix 1 : Installation guidée (recommandée)

Si tu **hésites** entre LITE et FULL, ou si c'est ta **première installation** :

```bash
sudo ./install.sh
```

Le script te présentera un menu :
```
╔══════════════════════════════════════════════╗
║        SIEM AFRICA — INSTALLATION            ║
║           Choisissez votre mode              ║
╚══════════════════════════════════════════════╝

  [1] MODE LITE (léger - 4 GB RAM)
  [2] MODE FULL (complet - 8 GB RAM)
  [3] Quitter

Votre choix :
```

### Choix 2 : Installation directe LITE

Si tu sais déjà que tu veux le mode léger :

```bash
sudo ./install-lite.sh
```

### Choix 3 : Installation directe FULL

Si tu sais déjà que tu veux le mode complet :

```bash
sudo ./install-full.sh
```

---

## 📋 Étape 3 : Suivre l'installation

L'installation se déroule en **8 étapes automatiques** :

### [1/8] Détection du système d'exploitation
```
Système détecté : Ubuntu 22.04.4 LTS
Architecture   : x86_64
Compatibilité  : ✅ OFFICIELLEMENT SUPPORTÉ
```

### [2/8] Sélection de la langue
```
[1] Français
[2] English
Votre choix :
```

### [3/8] Vérification des prérequis
```
✓ Droits root
✓ Connexion internet
✓ RAM disponible (8 GB)
✓ Espace disque (78 GB)
✓ Interface réseau détectée : ens33
✓ Ports disponibles
✓ Aucune installation existante
```

### [4/8] Préparation système
```
✓ Création groupe siem-africa
✓ Création user siem-ids
✓ Création répertoires /etc/siem-africa
✓ Création répertoires /var/lib/siem-africa
✓ Création répertoires /var/log/siem-africa
✓ Création répertoires /opt/siem-africa
```

### [5/8] Installation Snort IDS
```
✓ Ajout du dépôt Snort
✓ Installation Snort 2.9.20
✓ Configuration interface ens33
✓ Activation règles communautaires
✓ Démarrage service Snort
```

### [6/8] Installation Wazuh Manager
```
✓ Ajout du dépôt Wazuh
✓ Installation Wazuh Manager 4.14.0
✓ Configuration Manager
✓ Démarrage service wazuh-manager
```

### [7/8] (Mode FULL uniquement) Installation Indexer + Dashboard
```
✓ Installation Wazuh Indexer
✓ Configuration cluster single-node
✓ Installation Wazuh Dashboard
✓ Génération mot de passe admin
✓ Démarrage services
```

### [8/8] Finalisation
```
✓ Intégration Snort ↔ Wazuh
✓ Génération fichier d'état YAML
✓ Génération fichier RESUME.txt
✓ Exécution tests de validation
```

---

## ✅ Étape 4 : Validation après installation

### Vérifier les services actifs

```bash
# Snort
sudo systemctl status snort

# Wazuh Manager
sudo systemctl status wazuh-manager

# Mode FULL uniquement
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Consulter le résumé d'installation

```bash
sudo cat /etc/siem-africa/RESUME.txt
```

### Voir les alertes Wazuh en temps réel

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

### Voir les logs Snort

```bash
sudo tail -f /var/log/snort/alert
```

### Accéder au Wazuh Dashboard (Mode FULL)

1. Ouvre ton navigateur
2. Va sur `https://<IP_DU_SERVEUR>` (ex: `https://192.168.1.140`)
3. Accepte le certificat auto-signé
4. Login : `admin`
5. Password : celui affiché dans `RESUME.txt`

---

## 🔧 Étape 5 : Tests manuels (optionnel)

### Test 1 : Générer une alerte Snort

Depuis une **autre machine** sur le même réseau :

```bash
# Depuis la machine attaquante
nmap -sS <IP_SERVEUR_SIEM>
```

Puis sur le serveur SIEM :
```bash
sudo tail /var/log/snort/alert
# Tu devrais voir une alerte "SCAN nmap TCP"
```

### Test 2 : Vérifier que Wazuh reçoit les alertes

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep snort
```

---

## 🗑️ Désinstallation

Si tu veux **tout supprimer** et recommencer :

```bash
sudo ./uninstall.sh
```

Le script :
1. Arrête tous les services (Snort, Wazuh)
2. Désinstalle les paquets
3. Supprime les fichiers de config (`/etc/snort`, `/var/ossec`, etc.)
4. Supprime les users système (`siem-ids`)
5. Conserve les logs dans `/var/log/siem-africa/` pour audit

**Attention** : cette action est **irréversible**. Une confirmation sera demandée.

---

## 🛠️ Réparation

Si l'installation est **partiellement cassée** (services qui ne démarrent pas, config corrompue) :

```bash
sudo ./repair.sh
```

Le script tente :
1. Redémarrer les services
2. Restaurer les configurations par défaut
3. Regénérer le fichier d'état
4. Diagnostiquer les problèmes

Si la réparation échoue → désinstaller puis réinstaller.

---

## ❓ Problèmes courants et solutions

### ❌ "Installation interrompue : RAM insuffisante"

**Cause** : Tu as moins de RAM que le minimum requis.

**Solution** :
- Éteindre la VM
- Ajouter de la RAM dans les paramètres VirtualBox (8 GB recommandé pour FULL)
- Redémarrer la VM
- Relancer l'installation

### ❌ "Port 1514 déjà utilisé"

**Cause** : Une installation précédente de Wazuh n'est pas complètement supprimée.

**Solution** :
```bash
sudo ./uninstall.sh
# Attendre la fin
sudo ./install.sh
```

### ❌ "Interface réseau non détectée"

**Cause** : Problème de configuration VirtualBox.

**Solution** :
1. Arrêter la VM
2. VirtualBox → Configuration → Réseau
3. Activer "Carte 1" en mode "Bridge" ou "NAT"
4. Redémarrer la VM
5. Vérifier avec `ip a`

### ❌ "Wazuh Manager ne démarre pas"

**Solution** :
```bash
# Voir les logs détaillés
sudo journalctl -u wazuh-manager -n 50

# Vérifier la config
sudo cat /var/ossec/etc/ossec.conf

# Redémarrer
sudo systemctl restart wazuh-manager
```

### ❌ "Alerts.json est vide ou n'existe pas"

**Cause** : Wazuh Manager ne reçoit pas de logs.

**Solution** :
```bash
# Vérifier que Snort envoie bien à Wazuh
sudo tail /var/log/snort/alert

# Vérifier l'intégration
sudo grep -A 5 "snort-fast" /var/ossec/etc/ossec.conf
```

---

## 📞 Support

Pour toute question :
- Consulter `FAQ-JURY.md`
- Consulter les logs : `/var/log/siem-africa/install.log`
- Issue GitHub : [github.com/africa-siem/africa-siem/issues](https://github.com/africa-siem/africa-siem/issues)

---

## 🎯 Prochaine étape

Une fois le Module 1 installé avec succès :

```bash
# Installer le Module 2 (Base de données)
cd ../module-2-database
sudo ./install.sh
```

---

*Guide rédigé pour SIEM Africa v2.0 — IUT de Douala, 2026*
