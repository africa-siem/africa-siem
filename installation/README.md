# 🧹 SIEM Africa — Pack Auto-Cleanup v2.1

## 🎯 Ce que fait ce pack

Il ajoute à ton Module 1 un **mécanisme de nettoyage automatique** avant chaque installation. Fini les plantages dus à des résidus d'installations précédentes.

---

## 📦 Contenu du pack

```
siem-africa-cleanup/
├── clean-install.sh           ← SCRIPT TOUT-EN-UN : purge + install fraîche
├── core/
│   └── cleanup.sh             ← Fonctions de nettoyage (à ajouter à core/)
├── modules/
│   ├── 02-snort.sh            ← Version patchée (remplace l'original)
│   ├── 03-wazuh-manager.sh    ← Version patchée
│   ├── 04-wazuh-indexer.sh    ← Version patchée
│   └── 05-wazuh-dashboard.sh  ← Version patchée
├── PATCH-INSTRUCTIONS.md      ← Détails techniques (pour info)
└── README.md                  ← Ce fichier
```

---

## 🚀 Installation du pack

### Étape 1 : Copier les fichiers dans ton projet Module 1

Depuis la racine de ton Module 1 (`module-1-ids-siem/`) :

```bash
# 1. Ajouter le fichier cleanup.sh
cp siem-africa-cleanup/core/cleanup.sh core/cleanup.sh

# 2. Remplacer les 4 modules modifiés
cp siem-africa-cleanup/modules/02-snort.sh modules/02-snort.sh
cp siem-africa-cleanup/modules/03-wazuh-manager.sh modules/03-wazuh-manager.sh
cp siem-africa-cleanup/modules/04-wazuh-indexer.sh modules/04-wazuh-indexer.sh
cp siem-africa-cleanup/modules/05-wazuh-dashboard.sh modules/05-wazuh-dashboard.sh

# 3. Ajouter le script tout-en-un à la racine
cp siem-africa-cleanup/clean-install.sh clean-install.sh

# 4. Permissions d'exécution
chmod +x clean-install.sh
chmod +x modules/*.sh
```

### Étape 2 : Tester sur ta VM

```bash
# Option A : clean-install tout-en-un (recommandé après un échec)
sudo ./clean-install.sh

# Option B : install normal (les modules nettoient maintenant automatiquement)
sudo ./install.sh
```

---

## ✨ Ce qui change concrètement

### Avant (version 2.0)
```bash
sudo ./install.sh
# → Plante car Wazuh déjà partiellement installé
# → Erreur "readonly database", "/var/ossec existe déjà", etc.
# → Tu dois nettoyer à la main avant de relancer
```

### Après (version 2.1 avec ce pack)
```bash
sudo ./install.sh
# → Détecte Wazuh résiduel
# → Purge automatiquement
# → Réinstalle proprement
# → ✅ Installation réussie
```

---

## 🛠️ Les 10 fonctions de cleanup.sh

| Fonction | Utilité |
|---|---|
| `cleanup_snort` | Purge Snort (paquet, config, logs, service) |
| `cleanup_wazuh_manager` | Purge Wazuh Manager (+ `/var/ossec`) |
| `cleanup_wazuh_indexer` | Purge Wazuh Indexer (OpenSearch) |
| `cleanup_wazuh_dashboard` | Purge Wazuh Dashboard |
| `cleanup_filebeat` | Purge Filebeat (lié à Wazuh) |
| `cleanup_wazuh_repo` | Supprime le dépôt APT Wazuh |
| `cleanup_siem_state_files` | Supprime state.yaml, RESUME.txt, secrets (avec backup auto) |
| `cleanup_siem_users` | Supprime les users siem-* et le groupe |
| `cleanup_all` | **Purge TOUT** (utilisé par clean-install.sh) |
| `verify_cleanup` | Vérifie qu'il ne reste aucune trace |

---

## 🔐 Sécurité

- Les fichiers de config existants sont **sauvegardés** dans `/var/backups/siem-africa-old-<date>/` avant suppression.
- Les **paquets sont purgés** (`apt-get remove --purge`), pas juste désinstallés.
- Les **processus résiduels sont killés** avec `pkill -9` en cas de processus zombie.
- `daemon-reload` + `reset-failed` sont appelés pour nettoyer systemd.

---

## 📋 Checklist post-intégration

Après avoir copié les fichiers, vérifie :

- [ ] `ls core/cleanup.sh` → existe
- [ ] `ls modules/02-snort.sh` → présent et patché (contient `cleanup_snort`)
- [ ] `ls clean-install.sh` → existe et exécutable
- [ ] `bash -n clean-install.sh` → pas d'erreur de syntaxe
- [ ] `bash -n core/cleanup.sh` → pas d'erreur de syntaxe

---

## ⚠️ Limitation connue

Ce pack ne **résout pas automatiquement** les problèmes suivants :
- Bug de config Wazuh spécifique (si `ossec.conf` contient une erreur)
- Problème réseau (pas d'internet, DNS cassé)
- RAM insuffisante (< 4 GB pour lite, < 8 GB pour full)

Pour ces cas, les scripts afficheront un message d'erreur clair avec la commande de diagnostic à lancer.

---

## 🆘 Si ça plante encore

1. Lance `sudo ./clean-install.sh` (purge totale + install)
2. Si ça plante toujours, envoie-moi **les 20 dernières lignes** de :
   ```bash
   sudo cat /var/log/siem-africa/install.log | tail -20
   ```
3. Pour Snort : `sudo journalctl -u snort -n 30`
4. Pour Wazuh : `sudo journalctl -u wazuh-manager -n 30`

Avec ces logs je peux diagnostiquer le vrai problème.

---

*Pack v2.1 — SIEM Africa — Module 1 — IUT Douala 2026*
