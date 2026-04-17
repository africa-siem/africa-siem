# SIEM Africa

Solution SIEM open source gratuite pour les PME africaines.
Free open-source SIEM for African SMEs.

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | Installation | Snort IDS + Wazuh Manager |
| 2 | Database | SQLite 14 tables + 2 vues + 380 signatures MITRE ATT&CK |
| 3 | Agent | Python — corrélation, faux positifs, SMTP, iptables, honeypots |
| 4 | Dashboard | Django (port 8000) — thème dark/light, bilingue FR/EN, Chart.js |
| 5 | Mobile PWA | Notifications push, accès distant, mode offline |

## Prérequis

- Ubuntu 22.04 LTS (serveur dédié ou VM)
- Accès root (sudo)
- Connexion Internet
- 2 GB RAM minimum (4 GB recommandé), 10 GB disque

## Installation rapide

### Tout en une commande (modules 1+2+3)

```bash
curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/install_global.sh | sudo bash
```

### Module par module

```bash
# Module 1 — IDS + Manager
curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/installation/install.sh | sudo bash

# Module 1 — All-in-One (avec Wazuh Indexer)
curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/installation/installall.sh | sudo bash

# Module 2 — Base de données
curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/database/install.sh | sudo bash

# Module 3 — Agent
curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/agent/install.sh | sudo bash

# Module 4 — Dashboard
curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/dashboard/install.sh | sudo bash
```

## Architecture des permissions

```
Groupe système : siem-africa
/opt/siem-africa/                   chmod 775  siem-africa:siem-africa
/opt/siem-africa/siem_africa.db     chmod 664  siem-africa:siem-africa
/opt/siem-africa/.env               chmod 660  siem-africa:siem-africa
/opt/siem-africa/credentials.txt    chmod 640  siem-africa:siem-africa
/var/log/siem-africa/               chmod 755
```

## Licence

MIT — voir [LICENSE](LICENSE).

## Support

Issues : https://github.com/africa-siem/africa-siem/issues
