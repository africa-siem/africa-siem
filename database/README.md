# SIEM Africa — Module 2 : Base de données

> Base de données SQLite centralisée pour SIEM Africa.
> Stocke les signatures de détection, alertes, incidents, utilisateurs et configuration.

---

## 📋 Vue d'ensemble

Le Module 2 est **la mémoire du SIEM Africa**. C'est un fichier SQLite (`siem.db`) qui contient :

- **380 signatures** de détection (190 Wazuh + 190 Snort) avec descriptions pédagogiques FR/EN
- **14 tactiques + 137 techniques MITRE ATT&CK** pour la classification
- **10 catégories d'attaques** (Brute Force, Reconnaissance, Web Exploitation, etc.)
- **22 tables** organisées en 9 domaines fonctionnels
- **5 mécanismes** de gestion des faux positifs

Cette BDD est **lue et alimentée** par :
- L'**agent Python** (Module 3) pour matcher les alertes Wazuh contre les signatures
- Le **dashboard Django** (Module 4) pour afficher et gérer les alertes
- Les **rapports automatisés** (PDF/Excel)

---

## 🚀 Installation

### Prérequis

- Ubuntu 20.04+ ou Debian 11+
- Droits root (sudo)
- Module 1 (Snort + Wazuh) installé (recommandé mais pas obligatoire)
- ~5 MB d'espace disque

### Commande d'installation

```bash
sudo ./install_database.sh
```

L'installation est **interactive** et demande :
- Email de l'administrateur (défaut : `admin@siem-africa.local`)
- Nom de votre organisation

### Modes d'installation

```bash
sudo ./install_database.sh             # Mode normal (recommandé)
sudo ./install_database.sh --verbose   # Affiche toutes les commandes exécutées
sudo ./install_database.sh --silent    # Pour CI/CD (utilise valeurs par défaut)
sudo ./install_database.sh --no-admin  # Ne crée pas d'admin (déjà existant)
```

### Vérification post-install

```bash
sudo ./verify.sh                       # Vérification rapide (10 secondes)
sudo ./tests/run_all_tests.sh          # Suite complète de 5 tests
```

---

## 📁 Structure des fichiers

```
database/
├── install_database.sh         ← Script principal d'installation
├── verify.sh                   ← Script de vérification post-install
├── README.md                   ← Ce fichier
│
├── schema.sql                  ← Structure (22 tables, 3 vues, 9 triggers)
├── mitre_tactics.sql           ← 14 tactiques MITRE
├── mitre_techniques.sql        ← 137 techniques MITRE
├── categories.sql              ← 10 catégories d'attaques
├── signatures.sql              ← 380 signatures (190 Wazuh + 190 Snort)
├── seed.sql                    ← Rôles RBAC + admin + 33 settings
│
└── tests/
    ├── run_all_tests.sh        ← Lance tous les tests
    ├── test_schema.sh
    ├── test_signatures.sh
    ├── test_relationships.sh
    ├── test_performance.sh
    └── test_filters.sh
```

---

## 🗄️ Architecture de la BDD

### 22 tables organisées en 9 domaines

| Domaine | Tables |
|---------|--------|
| **1. MITRE & Signatures** | `mitre_tactics`, `mitre_techniques`, `signature_categories`, `signatures` |
| **2. Événements & Détection** | `raw_events`, `alerts`, `incidents` |
| **3. Faux positifs** | `alert_filters` |
| **4. Actifs & Contexte** | `assets` (avec colonnes Wazuh agents), `ip_reputation`, `threat_intel` |
| **5. Réponse Active** | `blocked_ips`, `honeypot_hits` |
| **6. Utilisateurs** | `roles`, `users`, `user_sessions` |
| **7. Communications** | `notifications`, `email_logs` |
| **8. Gouvernance** | `audit_log`, `settings`, `reports` |
| **9. Intelligence Artificielle** | `ai_explanations` |

### 3 vues pour le dashboard

- `v_alerts_enriched` : alertes enrichies avec signature, MITRE, asset, IP rep
- `v_dashboard_metrics` : KPIs principaux (alertes 24h, blocages actifs, etc.)
- `v_top_attackers_week` : top 20 IPs attaquantes sur 7 jours

---

## 🔑 Identification des signatures

**Particularité importante** : l'`id` de chaque signature est **directement le rule_id natif** de Snort ou Wazuh (pas un ID auto-incrémenté).

### Plages d'identifiants

| Plage | Source |
|-------|--------|
| `1 - 99 999` | Wazuh natif (ex: `5712` = SSH brute force) |
| `100 000 - 999 999` | Wazuh custom (réservé pour règles ajoutées localement) |
| `1 000 000 +` | Snort SID (ex: `2010493` = UNION SELECT) |

### Avantages

L'agent Python (Module 3) peut matcher une alerte en **une seule requête SQL** :

```python
signature = db.execute("SELECT * FROM signatures WHERE id = ?", (rule_id,)).fetchone()
```

Pas de table de mapping intermédiaire, pas de conversion. **Performance maximale.**

---

## 🛡️ Gestion des faux positifs (5 mécanismes)

C'est **LA** force du Module 2. Sans gestion des faux positifs, un SIEM est inutilisable en production.

### Mécanisme 1 : Pré-tagging à l'installation

**6 règles Wazuh notoirement bruyantes** sont pré-désactivées ou downgradées dès l'installation :

| rule_id | Règle | Action |
|---------|-------|--------|
| 5501 | PAM session opened | Ignorée |
| 5402 | sudo successful execution | Downgrade vers INFO |
| 5715 | SSH successful login | Downgrade vers INFO |
| 31100 | Apache normal access | Ignorée |
| 5740 | SSH disconnect before auth | Downgrade vers INFO |
| 31509 | WordPress login attempt (single) | Downgrade vers INFO |

### Mécanisme 2 : Workflow manuel "Marquer comme faux positif"

Quand l'admin marque une alerte `FALSE_POSITIVE` dans le dashboard :
- Le statut est mis à jour
- Un trigger SQL diminue automatiquement la `confidence` de la signature
- Le dashboard propose de créer un filtre pour les futures alertes similaires

### Mécanisme 3 : Bruit-killer automatique

Si une règle génère **> 100 alertes/heure dont > 80% sont des FP**, un filtre temporaire (24h) est créé automatiquement et un email de synthèse est envoyé à l'admin.

Configurable dans `settings` :
- `noise_killer_enabled` (défaut : `1`)
- `noise_killer_threshold_per_hour` (défaut : `100`)
- `noise_killer_fp_ratio_threshold` (défaut : `0.8`)

### Mécanisme 4 : Confidence dynamique

Deux triggers SQL ajustent automatiquement la `confidence` de chaque signature :

```sql
-- Diminue confidence si FALSE_POSITIVE (max -50 du score initial)
CREATE TRIGGER trg_decrease_confidence_on_fp ...

-- Augmente confidence si RESOLVED (max +30)
CREATE TRIGGER trg_increase_confidence_on_resolved ...
```

### Mécanisme 5 : Table `alert_filters` dédiée

Permet à l'admin de définir des filtres précis :
- Par règle Wazuh/Snort
- Par IP source/destination
- Par utilisateur (regex)
- Par horaire / jour de semaine
- Action : IGNORE / DOWNGRADE / NOTIFY_ONLY

---

## 🤖 Intégration IA (basique en v1)

La table `ai_explanations` met en cache les explications IA pour les alertes.

**Fournisseur par défaut** : Ollama local (LLaMA 3.2 3B), gratuit et privé.

```sql
-- Exemple d'utilisation par le dashboard
SELECT explanation_fr FROM ai_explanations WHERE alert_id = 123;

-- Si vide → appel à l'API IA → INSERT dans ai_explanations → return
```

Configurable dans `settings` :
- `ai_provider` : `ollama`, `claude`, `openai`, `mistral`, `gemini`
- `ai_model` : `llama3.2:3b` par défaut
- `ai_api_endpoint` : `http://localhost:11434` (Ollama local)
- `ai_enabled` : `1`

---

## 📧 SMTP & Emails

La table `email_logs` trace tous les emails envoyés par l'agent (Module 3) avec :
- Statut (PENDING/SENT/FAILED)
- Anti-spam interne (`dedup_key`)
- Lien vers l'alerte/incident source

**Configuration SMTP** : faite par le **Module 3** lors de son installation (interactive : email admin + procédure mot de passe + test d'envoi).

7 paramètres SMTP sont pré-créés vides dans `settings` :
- `smtp_method` (POSTFIX ou RELAY)
- `smtp_relay_host`, `smtp_relay_port`
- `smtp_relay_user`, `smtp_relay_password`
- `smtp_from_address`, `smtp_admin_recipient`

---

## 🔐 Sécurité

### Permissions fichier

```
Propriétaire  : siem-db
Groupe        : siem-africa
Permissions   : 660 (lecture/écriture user et groupe)
```

### Mots de passe

- Hash **argon2id** (recommandation OWASP)
- Génération aléatoire 16 caractères pour l'admin par défaut
- `must_change_pwd = 1` à la première connexion

### Audit

La table `audit_log` trace **toutes les actions sensibles** :
- Connexions/déconnexions
- Modifications de configuration
- Changements de statut d'alertes
- Actions de blocage/déblocage IP
- Utilisations IA

Conforme RGPD et bonnes pratiques de conformité.

---

## 🚀 Évolutivité (perspectives v2)

L'architecture est conçue pour supporter à terme :

- **PWA mobile** : table `mobile_devices` à ajouter
- **IA conversationnelle** : tables `ai_conversations`, `ai_messages`, `ai_decisions_log`
- **Multi-tenant** : ajouter `tenant_id` aux tables principales
- **Migration PostgreSQL** : SQL standard utilisé pour faciliter le portage
- **Cloudflare integration** : settings pré-prévus dans `settings`

---

## 📊 Statistiques de la BDD installée

| Élément | Quantité |
|---------|----------|
| Tables | 22 |
| Vues | 3 |
| Triggers | 9 |
| Index | 88 |
| Tactiques MITRE | 14 |
| Techniques MITRE | 137 |
| Catégories d'attaques | 10 |
| Signatures totales | 380 (190 Wazuh + 190 Snort) |
| Rôles RBAC | 4 |
| Settings initiaux | 33 |
| Filtres pré-taggés | 6 |

**Taille typique de la BDD après seed** : ~2 MB (vide d'alertes).

---

## 🔧 Maintenance

### Inspecter la BDD

```bash
sudo -u siem-db sqlite3 /var/lib/siem-africa/siem.db
```

### Voir les alertes récentes

```bash
sudo -u siem-db sqlite3 /var/lib/siem-africa/siem.db \
    "SELECT * FROM v_alerts_enriched ORDER BY first_seen DESC LIMIT 10;"
```

### Voir les métriques dashboard

```bash
sudo -u siem-db sqlite3 /var/lib/siem-africa/siem.db \
    "SELECT * FROM v_dashboard_metrics;"
```

### Backup manuel

```bash
sudo cp /var/lib/siem-africa/siem.db \
    /var/lib/siem-africa/siem.db.backup.$(date +%Y%m%d)
```

### Purge des vieux événements

```bash
# Purger les raw_events de plus de 30 jours
sudo -u siem-db sqlite3 /var/lib/siem-africa/siem.db \
    "DELETE FROM raw_events WHERE event_timestamp < datetime('now','-30 days');"

# VACUUM pour récupérer l'espace
sudo -u siem-db sqlite3 /var/lib/siem-africa/siem.db "VACUUM;"
```

---

## 🆘 Dépannage

### "Database is locked"

```bash
# Vérifier qu'aucun processus ne bloque
sudo lsof /var/lib/siem-africa/siem.db

# Si nécessaire, arrêter l'agent (Module 3) temporairement
sudo systemctl stop siem-africa-agent
```

### "No such table"

La BDD a probablement été créée sans certains fichiers SQL. Réinstaller :

```bash
sudo ./install_database.sh
```

### Permission denied

```bash
# Vérifier les permissions
sudo ls -la /var/lib/siem-africa/

# Réappliquer si besoin
sudo chown -R siem-db:siem-africa /var/lib/siem-africa/
sudo chmod 660 /var/lib/siem-africa/siem.db
```

---

## 📞 Support

- **Documentation projet** : voir le repo principal
- **Logs d'installation** : `/var/log/siem-africa/db-install.log`
- **Credentials** : `/root/siem_credentials.txt`

---

## 📝 Licence

SIEM Africa est un projet open-source destiné aux PME africaines.
Voir le fichier LICENSE du repo principal.
