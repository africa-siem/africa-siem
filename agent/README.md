# Module 3 — Agent intelligent SIEM Africa

Agent Python qui consomme la base de données SIEM Africa, lit les alertes Wazuh en temps réel, corrèle, enrichit, filtre les faux positifs, déclenche des réponses actives et notifie.

## 🚀 Installation rapide

```bash
# Clone (ou télécharge) le repo
cd ~ && git clone https://github.com/africa-siem/africa-siem.git
cd africa-siem/agent

# Rendre exécutables
chmod +x install_agent.sh configure_smtp.sh verify.sh uninstall_agent.sh tests/*.sh

# Installation interactive
sudo ./install_agent.sh

# Vérification
sudo ./verify.sh

# Tests automatisés (5 tests)
sudo ./tests/run_all_tests.sh
```

L'installation interactive te demandera :
- Choix de la langue (FR/EN)
- Email destinataire des alertes
- Configuration SMTP (test envoi inclus)
- Confirmation install Ollama (~2 GB)
- Sévérité minimum pour déclencher des emails

## 📁 Structure

```
agent/
├── README.md
├── install_agent.sh            # Installation interactive complète
├── configure_smtp.sh           # Reconfiguration SMTP
├── verify.sh                   # Vérification post-install
├── uninstall_agent.sh          # Désinstallation propre
├── agent.py                    # Point d'entrée
├── modules/                    # 12 modules Python
│   ├── config.py               # Chargement .env + override BDD
│   ├── db.py                   # SQLite WAL + FK ON + retry
│   ├── wazuh_reader.py         # Lecture alerts.json
│   ├── alert_processor.py      # Pipeline orchestrateur
│   ├── filters.py              # 5 mécanismes faux positifs
│   ├── correlator.py           # Corrélation (déduplication)
│   ├── enrichment.py           # MITRE + IP rep + stats
│   ├── notifier.py             # Email SMTP + dashboard
│   ├── active_response.py      # Blocage iptables auto
│   ├── honeypot.py             # SSH/HTTP/MySQL faux services
│   ├── ai_explainer.py         # Cache + Ollama
│   ├── noise_killer.py         # Bruit-killer cron
│   └── audit.py                # Audit log auto
├── config/
│   └── agent.env.template      # Template config
├── systemd/
│   └── siem-agent.service      # Service systemd
└── tests/                      # 5 tests automatisés
    ├── run_all_tests.sh
    ├── test_db_access.sh
    ├── test_signature_lookup.sh
    ├── test_filters.sh
    ├── test_email.sh
    └── test_systemd.sh
```

## ⚙️ Fonctionnalités

| Feature | Détails |
|---|---|
| **Lecture temps réel** | `alerts.json` Wazuh (méthode officielle, pas l'API) |
| **Matching direct** | `signatures.id = rule_id` Wazuh / SID Snort |
| **5 mécanismes FP** | Pré-tagging, alert_filters, bruit-killer auto, confidence dynamique, FALSE_POSITIVE manuel |
| **Corrélation** | Dédupe alertes répétitives (event_count) |
| **Enrichissement** | MITRE ATT&CK, IP réputation, géoloc, stats locales |
| **Honeypots** | SSH (2222), HTTP (8888), MySQL (3307) avec capture credentials |
| **Active Response** | Blocage iptables auto pour CRITICAL avec déblocage programmé |
| **IA Ollama** | LLaMA 3.2 3B local, explications FR/EN, cache intelligent |
| **Notifications** | Email SMTP bilingue + dashboard, anti-spam dedup_key |
| **Audit complet** | 100% des actions agent dans `audit_log` |
| **Bruit-killer** | Cron horaire détection alert storms → filtres auto |
| **Survie reboot** | Restauration des règles iptables au démarrage agent |

## 🔧 Configuration

Fichier : `/etc/siem-africa/agent.env` (permissions 640 root:siem-africa)

Reconfigurer SMTP plus tard :
```bash
sudo ./configure_smtp.sh
```

## 🧪 Tests automatisés

```bash
sudo ./tests/run_all_tests.sh
```

5 tests :
1. **Accès BDD** : lecture/écriture par siem-agent
2. **Lookup signature** : 380 sigs, JOIN MITRE
3. **5 mécanismes FP** : is_noisy, alert_filters, triggers SQL
4. **Email SMTP** : envoi réel (si configuré)
5. **Service systemd** : actif, capabilities, restart policy

## 🛑 Désinstallation

```bash
sudo ./uninstall_agent.sh
```

Supprime :
- Service systemd
- `/opt/siem-africa-agent/`
- Utilisateur `siem-agent`
- Section [MODULE 3] du fichier credentials
- Optionnellement Ollama et son modèle

Conserve :
- Module 1 (Wazuh)
- Module 2 (BDD)
- Groupe `siem-africa`

## 📊 Suivi

```bash
# Statut
sudo systemctl status siem-agent

# Logs temps réel
sudo journalctl -u siem-agent -f

# Logs fichier
sudo tail -f /var/log/siem-africa/agent.log

# Stats BDD
sudo -u siem-agent sqlite3 /var/lib/siem-africa/siem.db \
    "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
```

## 🔐 Sécurité

- User `siem-agent` non-login (`/usr/sbin/nologin`)
- Fichier config en 640 (lecture root + groupe siem-africa)
- BDD en 660 (lecture/écriture user+groupe)
- Capabilities minimales : `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE`
- Whitelist iptables hardcodée (jamais bloquer 127.0.0.1, ::1, IP serveur)
- Audit complet dans `audit_log`

## 📄 Prérequis

- Linux Ubuntu 22.04 / 24.04 (Debian 11/12 compatible)
- **Module 1** (Wazuh + Snort) installé
- **Module 2** (BDD) installé
- Python 3.10+
- iptables
- ~3 GB d'espace disque (avec Ollama et modèle)
- Connexion Internet (pour install Ollama)
