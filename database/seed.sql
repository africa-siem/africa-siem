-- ============================================================================
-- SIEM AFRICA - Module 2
-- database/seed.sql
-- ============================================================================
-- Données initiales :
--   • 4 rôles RBAC (admin, analyst, operator, viewer)
--   • 1 utilisateur admin (mot de passe généré par install_database.sh)
--   • 15 paramètres système (dont 7 pour SMTP, vides à l'install)
--   • 6 filtres pré-taggés pour les règles Wazuh notoirement bruyantes
--   • 8 politiques de rétention par défaut
-- ============================================================================


-- ============================================================================
-- ROLES RBAC
-- ============================================================================

INSERT OR IGNORE INTO roles (id, code, name, description, description_fr, permissions, is_system) VALUES
(1, 'ADMIN', 'Administrator',
 'Full access to all features. Can manage users, configuration, and all data.',
 'Accès complet à toutes les fonctionnalités. Peut gérer utilisateurs, configuration, et toutes les données.',
 '["alerts.*","incidents.*","users.*","assets.*","config.*","reports.*","ai.*","filters.*","blocks.*","audit.*"]',
 1),

(2, 'ANALYST', 'Security Analyst',
 'Can view and manage alerts, incidents, blocks. Cannot manage users or system config.',
 'Peut voir et gérer alertes, incidents, blocages. Ne peut pas gérer utilisateurs ou configuration système.',
 '["alerts.view","alerts.acknowledge","alerts.resolve","incidents.*","blocks.create","blocks.view","filters.create","filters.view","ai.use","reports.view","reports.create"]',
 1),

(3, 'OPERATOR', 'Security Operator',
 'Can view alerts and acknowledge them. Limited to read-only on most areas.',
 'Peut voir les alertes et les acquitter. Lecture seule sur la plupart des zones.',
 '["alerts.view","alerts.acknowledge","incidents.view","blocks.view","reports.view","ai.use"]',
 1),

(4, 'VIEWER', 'Read-only Viewer',
 'Read-only access to all dashboard data. Cannot modify anything.',
 'Accès lecture seule à toutes les données du dashboard. Ne peut rien modifier.',
 '["alerts.view","incidents.view","assets.view","blocks.view","reports.view"]',
 1);


-- ============================================================================
-- UTILISATEUR ADMIN PAR DÉFAUT
-- Note : email et password_hash seront mis à jour par install_database.sh
-- Le placeholder ici permet juste à la BDD d'avoir un user_id=1 valide
-- ============================================================================

-- L'admin sera inséré par install_database.sh avec :
--   email   : valeur saisie ou admin@siem-africa.local par défaut
--   password : aléatoire 16 chars, hashé avec argon2id
-- (seed.sql ne fait que préparer les rôles)


-- ============================================================================
-- POLITIQUES DE RÉTENTION DES DONNÉES (table data_retention non créée v1)
-- → reportées en perspective v2, géré via paramètres settings ci-dessous
-- ============================================================================


-- ============================================================================
-- PARAMÈTRES SYSTÈME (settings)
-- ============================================================================

INSERT OR IGNORE INTO settings (key, value, value_type, category, description, description_fr, is_secret, is_public, is_editable) VALUES

-- ============= ORGANISATION =============
('org_name', 'SIEM Africa', 'string', 'organization',
 'Organization name displayed in UI and emails',
 'Nom de l''organisation affiché dans l''UI et les emails',
 0, 1, 1),

('org_country', '', 'string', 'organization',
 'Organization country (ISO code, e.g. CM, CI, SN)',
 'Pays de l''organisation (code ISO, ex: CM, CI, SN)',
 0, 1, 1),

('org_timezone', 'Africa/Abidjan', 'string', 'organization',
 'Default timezone for the organization',
 'Fuseau horaire par défaut de l''organisation',
 0, 1, 1),

-- ============= DÉTECTION =============
('block_threshold_attempts', '10', 'int', 'detection',
 'Number of failed attempts before automatic IP block',
 'Nombre de tentatives échouées avant blocage automatique d''IP',
 0, 1, 1),

('block_threshold_window_minutes', '5', 'int', 'detection',
 'Time window (minutes) for counting failed attempts',
 'Fenêtre temporelle (minutes) pour compter les tentatives échouées',
 0, 1, 1),

('block_default_duration_hours', '24', 'int', 'detection',
 'Default IP block duration in hours (0 = permanent)',
 'Durée par défaut du blocage IP en heures (0 = permanent)',
 0, 1, 1),

('alert_correlation_window_seconds', '60', 'int', 'detection',
 'Time window for correlating events into single alert',
 'Fenêtre temporelle pour corréler les événements en une seule alerte',
 0, 1, 1),

-- ============= GESTION FAUX POSITIFS =============
('noise_killer_enabled', '1', 'bool', 'detection',
 'Enable automatic noise detection and filtering',
 'Activer la détection et le filtrage automatique du bruit',
 0, 1, 1),

('noise_killer_threshold_per_hour', '100', 'int', 'detection',
 'Alert count per hour to trigger auto-filter creation',
 'Nombre d''alertes par heure pour déclencher la création de filtre auto',
 0, 1, 1),

('noise_killer_fp_ratio_threshold', '0.8', 'string', 'detection',
 'Minimum ratio of FP among alerts to create auto-filter (0.8 = 80%)',
 'Ratio minimum de faux positifs parmi les alertes pour créer un filtre auto (0.8 = 80%)',
 0, 1, 1),

-- ============= SMTP (vide à l'install, configuré par Module 3) =============
('smtp_method', 'POSTFIX', 'string', 'smtp',
 'SMTP method: POSTFIX (local) or RELAY (external SMTP)',
 'Méthode SMTP : POSTFIX (local) ou RELAY (SMTP externe)',
 0, 0, 1),

('smtp_relay_host', '', 'string', 'smtp',
 'External SMTP relay host (e.g. smtp.gmail.com)',
 'Hôte SMTP externe (ex: smtp.gmail.com)',
 0, 0, 1),

('smtp_relay_port', '587', 'int', 'smtp',
 'External SMTP port (typically 587 for TLS)',
 'Port SMTP externe (typiquement 587 pour TLS)',
 0, 0, 1),

('smtp_relay_user', '', 'string', 'smtp',
 'SMTP authentication user (email address)',
 'Utilisateur d''authentification SMTP (adresse email)',
 0, 0, 1),

('smtp_relay_password', '', 'secret', 'smtp',
 'SMTP authentication password (App Password for Gmail)',
 'Mot de passe SMTP (Mot de Passe d''Application pour Gmail)',
 1, 0, 1),

('smtp_from_address', '', 'string', 'smtp',
 'Email sender address (e.g. alerts@yourcompany.com)',
 'Adresse email expéditrice (ex: alerts@votreentreprise.com)',
 0, 1, 1),

('smtp_admin_recipient', '', 'string', 'smtp',
 'Default admin email recipient for critical alerts',
 'Destinataire admin par défaut pour les alertes critiques',
 0, 1, 1),

-- ============= NOTIFICATIONS =============
('notify_email_enabled', '0', 'bool', 'notifications',
 'Enable email notifications (set to 1 after SMTP config)',
 'Activer les notifications email (mettre à 1 après config SMTP)',
 0, 1, 1),

('notify_severity_min', 'HIGH', 'string', 'notifications',
 'Minimum severity for email notifications (INFO/LOW/MEDIUM/HIGH/CRITICAL)',
 'Sévérité minimum pour les notifications email',
 0, 1, 1),

('notify_dedup_window_minutes', '60', 'int', 'notifications',
 'Time window for email deduplication (anti-spam)',
 'Fenêtre temporelle pour déduplication emails (anti-spam)',
 0, 1, 1),

-- ============= IA =============
('ai_provider', 'ollama', 'string', 'ai',
 'AI provider: ollama (local), claude, openai, mistral, gemini',
 'Fournisseur IA : ollama (local), claude, openai, mistral, gemini',
 0, 1, 1),

('ai_model', 'llama3.2:3b', 'string', 'ai',
 'AI model name (e.g. llama3.2:3b for Ollama, claude-opus-4-7 for Anthropic)',
 'Nom du modèle IA (ex: llama3.2:3b pour Ollama)',
 0, 1, 1),

('ai_api_endpoint', 'http://localhost:11434', 'string', 'ai',
 'AI API endpoint URL (Ollama default: http://localhost:11434)',
 'URL endpoint API IA (Ollama par défaut : http://localhost:11434)',
 0, 1, 1),

('ai_api_key', '', 'secret', 'ai',
 'API key for cloud AI providers (not needed for Ollama)',
 'Clé API pour fournisseurs IA cloud (non nécessaire pour Ollama)',
 1, 0, 1),

('ai_enabled', '1', 'bool', 'ai',
 'Enable AI explanations feature',
 'Activer la fonctionnalité d''explications IA',
 0, 1, 1),

('ai_cache_enabled', '1', 'bool', 'ai',
 'Cache AI responses to reduce API calls',
 'Mettre en cache les réponses IA pour réduire les appels API',
 0, 1, 1),

-- ============= RÉTENTION DES DONNÉES =============
('retention_alerts_days', '90', 'int', 'retention',
 'Number of days to keep alerts before auto-purge',
 'Nombre de jours de conservation des alertes avant purge auto',
 0, 1, 1),

('retention_raw_events_days', '30', 'int', 'retention',
 'Number of days to keep raw events',
 'Nombre de jours de conservation des événements bruts',
 0, 1, 1),

('retention_audit_log_days', '365', 'int', 'retention',
 'Audit log retention (default: 1 year for compliance)',
 'Conservation du journal d''audit (défaut : 1 an pour conformité)',
 0, 1, 1),

('retention_ai_explanations_days', '180', 'int', 'retention',
 'AI explanations cache retention',
 'Conservation du cache des explications IA',
 0, 1, 1),

-- ============= INSTALLATION =============
('schema_version', '1.0.0', 'string', 'system',
 'Database schema version',
 'Version du schéma de base de données',
 0, 0, 0),

('install_date', '', 'string', 'system',
 'Initial installation date (set by install_database.sh)',
 'Date d''installation initiale',
 0, 0, 0),

('module_2_status', 'INSTALLED', 'string', 'system',
 'Module 2 (database) installation status',
 'Statut d''installation du Module 2 (database)',
 0, 0, 0);


-- ============================================================================
-- FILTRES PRÉ-TAGGÉS pour règles Wazuh notoirement bruyantes
-- (Mécanisme 1/5 de gestion des faux positifs)
-- ============================================================================

INSERT OR IGNORE INTO alert_filters (filter_uuid, name, signature_id, action, downgrade_to, filter_type, reason, is_active) VALUES

('flt-pretag-001', 'Auto-tag: PAM session opened (5501)', 5501, 'IGNORE', NULL, 'PRE_TAGGED',
 'Wazuh rule 5501 (PAM session opened) is notoriously noisy. Disabled by default. Re-enable if specific use case requires it.',
 1),

('flt-pretag-002', 'Auto-tag: sudo successful execution (5402)', 5402, 'DOWNGRADE', 'INFO', 'PRE_TAGGED',
 'Wazuh rule 5402 (sudo successful) generates many alerts in normal admin activity. Downgraded to INFO by default.',
 1),

('flt-pretag-003', 'Auto-tag: SSH successful login (5715)', 5715, 'DOWNGRADE', 'INFO', 'PRE_TAGGED',
 'Wazuh rule 5715 (SSH login success) is normal admin activity. Downgraded to INFO. Custom filters needed for unusual logins.',
 1),

('flt-pretag-004', 'Auto-tag: SSH disconnect before auth (5740)', 5740, 'DOWNGRADE', 'INFO', 'PRE_TAGGED',
 'Wazuh rule 5740 generates noise from network scanners. Downgraded to INFO.',
 1),

('flt-pretag-005', 'Auto-tag: WP login attempt single (31509)', 31509, 'DOWNGRADE', 'INFO', 'PRE_TAGGED',
 'Single WordPress login attempts are normal. Brute force is detected by separate rule 31510.',
 1),

('flt-pretag-006', 'Auto-tag: PAM single failed login (5503)', 5503, 'DOWNGRADE', 'INFO', 'PRE_TAGGED',
 'Wazuh rule 5503 (single PAM failure) generates noise. Real attacks are detected by 5551 (multiple failures).',
 1);


-- ============================================================================
-- FIN seed.sql
-- 4 rôles RBAC + 33 settings + 6 filtres pré-taggés
-- ============================================================================
