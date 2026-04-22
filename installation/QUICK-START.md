# ⚡ QUICK START — Démarrage rapide SIEM Africa

> Tu es pressé ? Voici comment démarrer en 5 minutes.

---

## 🎯 Tu veux juste installer ?

```bash
# 1. Cloner le repo
cd /opt
sudo git clone https://github.com/africa-siem/africa-siem.git
cd africa-siem/module-1-ids-siem

# 2. Rendre les scripts exécutables
sudo chmod +x install*.sh core/*.sh modules/*.sh scripts/*.sh tests/*.sh

# 3. Lancer l'installation (menu interactif)
sudo ./install.sh
```

Choisis **LITE** (4 GB RAM) ou **FULL** (8 GB RAM + interface web Wazuh).

---

## 🧪 Tu veux tester que ça marche ?

```bash
# Test global (Snort + Wazuh + intégration)
sudo /opt/siem-africa/module-1/tests/test-integration.sh

# Tests individuels
sudo /opt/siem-africa/module-1/tests/test-snort.sh
sudo /opt/siem-africa/module-1/tests/test-wazuh.sh
```

---

## 📋 Tu veux voir l'état de ton installation ?

```bash
# Résumé lisible
sudo cat /etc/siem-africa/RESUME.txt

# État détaillé YAML
sudo cat /etc/siem-africa/siem-africa.state.yaml

# Password admin Wazuh Dashboard (mode FULL)
sudo cat /etc/siem-africa/secrets/wazuh-admin.pwd
```

---

## 🔧 Tu veux vérifier les services ?

```bash
# Statut complet
sudo systemctl status snort wazuh-manager

# Mode FULL : ajouter
sudo systemctl status wazuh-indexer wazuh-dashboard

# Redémarrer tout
sudo systemctl restart snort wazuh-manager
```

---

## 👀 Tu veux voir les alertes en temps réel ?

```bash
# Alertes Snort brutes
sudo tail -f /var/log/snort/alert

# Alertes Wazuh (JSON enrichi)
sudo tail -f /var/ossec/logs/alerts/alerts.json

# Avec mise en forme JSON
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq '.'
```

---

## 🚨 Tu veux tester une détection ?

**Depuis une autre machine sur le même réseau** :

```bash
# Scan de ports (nmap)
nmap -sS <IP_DU_SIEM>

# Brute force SSH (avec hydra - à installer)
sudo apt install hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<IP_DU_SIEM>

# DDoS simulé (avec hping3)
sudo apt install hping3
sudo hping3 -S --flood -p 80 <IP_DU_SIEM>
```

**Puis vérifier sur le SIEM** :
```bash
sudo tail /var/log/snort/alert
sudo tail /var/ossec/logs/alerts/alerts.json
```

---

## 🔄 Tu veux mettre à jour les règles Snort ?

```bash
# Mise à jour manuelle
sudo /opt/siem-africa/module-1/scripts/update-rules.sh

# Le cron automatique est déjà configuré (chaque lundi à 3h)
sudo cat /etc/cron.d/siem-africa-rules-update
```

---

## 🛠️ Tu as un problème ?

```bash
# 1. Essayer la réparation automatique
sudo /opt/siem-africa/module-1/repair.sh

# 2. Consulter les logs
sudo journalctl -u snort -n 50
sudo journalctl -u wazuh-manager -n 50
sudo cat /var/log/siem-africa/install.log

# 3. En dernier recours : désinstaller + réinstaller
sudo /opt/siem-africa/module-1/uninstall.sh
sudo /opt/siem-africa/module-1/install.sh
```

---

## 🗑️ Tu veux tout désinstaller ?

```bash
# Désinstallation standard (conserve les logs)
sudo /opt/siem-africa/module-1/uninstall.sh

# Désinstallation complète (efface tout)
sudo /opt/siem-africa/module-1/uninstall.sh --purge

# Sans confirmation
sudo /opt/siem-africa/module-1/uninstall.sh --force
```

---

## 📚 Documentation complète

- **README.md** : Présentation du module
- **INSTALL.md** : Guide d'installation détaillé
- **FAQ-JURY.md** : Préparation soutenance
- **CHANGELOG.md** : Évolution du projet

---

## 🌐 Accès Web (Mode FULL uniquement)

Une fois l'installation terminée :

```
URL      : https://<IP_DU_SIEM>
Login    : admin
Password : (voir /etc/siem-africa/secrets/wazuh-admin.pwd)
```

⚠️ **Le certificat HTTPS est auto-signé** → votre navigateur affichera un avertissement, c'est normal. Cliquez sur "Continuer vers le site" (ou équivalent).

---

## 🎯 Commandes à retenir

| Commande | Action |
|----------|--------|
| `sudo ./install.sh` | Menu d'installation |
| `sudo ./install-lite.sh` | Install directe LITE |
| `sudo ./install-full.sh` | Install directe FULL |
| `sudo ./uninstall.sh` | Désinstaller |
| `sudo ./repair.sh` | Réparer |
| `sudo ./tests/test-integration.sh` | Tester |
| `sudo cat /etc/siem-africa/RESUME.txt` | Voir résumé |

---

## ⚠️ Important

**Avant d'installer sur un serveur réel** :
- Sauvegarder les données importantes
- Vérifier que l'interface réseau détectée est la bonne
- Configurer un mot de passe admin fort
- Ouvrir les ports dans le firewall
- Planifier les sauvegardes régulières

**En cas de doute, toujours tester d'abord sur une VM** (VirtualBox, VMware).

---

*Bon déploiement ! 🚀*
