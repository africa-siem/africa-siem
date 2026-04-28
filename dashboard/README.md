# Module 4 — Dashboard SIEM Africa

Dashboard web Django pour la supervision et la réponse aux incidents.

## 🚀 Installation

```bash
curl -sL https://raw.githubusercontent.com/africa-siem/africa-siem/main/dashboard/install.sh | sudo bash
```

## 🎯 Fonctionnalités

### Surveillance
- **Dashboard** : 4 métriques live + 3 graphiques Chart.js (timeline 7j, distribution horaire, catégories)
- **Alertes** : liste filtrée par sévérité/statut, pagination, export CSV
- **MITRE ATT&CK** : matrice complète 14 tactiques + techniques avec hits live
- **Honeypot** : pièges SSH/HTTP/MySQL avec stats par type

### Réponse
- **Filtres FP** : création avec autocomplete signatures, suppression
- **IPs bloquées** : déblocage manuel (l'agent retire la règle iptables)

### Intelligence (IA Ollama)
- **Résumé exécutif** : généré pour managers en 150 mots
- **Suggestions de filtres** : analyse 7j, propose des filtres FP
- **Explication d'alerte** : on-demand avec cache (table ai_explanations)
- **Chatbot conversationnel** : a accès aux alertes et métriques en temps réel

### Administration
- **Utilisateurs** : CRUD avec rôles (ADMIN/ANALYST/VIEWER/AUDITOR)
- **Paramètres** : édition des 33+ settings du Module 2 (incluant SMTP, IA, etc.)

## 🔐 Sécurité

- Auth bcrypt (table `users` du Module 2)
- RBAC complet (permissions par rôle)
- Audit log automatique de toutes les actions admin
- Sessions DB séparée (`dashboard_sessions.db`)
- Permissions strictes : `750 siem-dashboard:siem-africa`
- Config en `640 root:siem-africa`

## 📊 Stack

- Django 4.2 + gunicorn
- SQLite raw queries (pas de Django ORM sur la BDD principale)
- Chart.js 4 (graphiques)
- Whitenoise (static files)
- Ollama (IA, optionnel)

## 🌐 Accès

Une fois installé : `http://<IP-VM>:8000`

Identifiants : ceux de l'admin créé au Module 2.

## 📋 Commandes utiles

```bash
sudo systemctl status siem-dashboard
sudo journalctl -u siem-dashboard -f
sudo systemctl restart siem-dashboard
```

## 🛠️ Reconfiguration

Modifier `/etc/siem-africa/dashboard.env` puis redémarrer le service.
