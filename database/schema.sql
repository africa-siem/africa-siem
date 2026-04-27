-- ============================================================================
-- SIEM AFRICA - Module 2 : Base de données SQLite
-- database/schema.sql
-- ============================================================================
--
-- Schéma complet : 22 tables organisées en 9 domaines fonctionnels.
--
-- ARCHITECTURE GÉNÉRALE :
--
--   Domaine 1 : MITRE & Signatures            (4 tables)
--   Domaine 2 : Événements & Détection        (3 tables)
--   Domaine 3 : Gestion des faux positifs     (1 table)
--   Domaine 4 : Actifs & Contexte             (3 tables)
--   Domaine 5 : Réponse Active                (2 tables)
--   Domaine 6 : Utilisateurs                  (3 tables)
--   Domaine 7 : Communications                (2 tables)
--   Domaine 8 : Gouvernance                   (3 tables)
--   Domaine 9 : Intelligence Artificielle     (1 table)
--
-- CONVENTIONS :
--   - Clés primaires : id INTEGER PRIMARY KEY (AUTOINCREMENT sauf signatures)
--   - UUIDs publics  : *_uuid TEXT UNIQUE (pour exposition API)
--   - Timestamps     : TEXT format ISO 8601 (CURRENT_TIMESTAMP standard SQL)
--   - Soft delete    : deleted_at TEXT NULL (RGPD-ready)
--   - Foreign keys   : ON DELETE RESTRICT par défaut
--   - Métadonnées    : metadata TEXT (JSON extensible)
--
-- IDENTIFIANTS DE SIGNATURES :
--   La table signatures utilise comme PRIMARY KEY le rule_id natif :
--     - 1-99999       : règles Wazuh natives
--     - 100000-999999 : règles Wazuh custom (réservé pour extension)
--     - 1000000+      : règles Snort (SID)
--
-- ============================================================================

-- Activation des clés étrangères (désactivées par défaut dans SQLite)
PRAGMA foreign_keys = ON;

-- Mode WAL pour meilleures performances en concurrence
PRAGMA journal_mode = WAL;

-- Synchronisation NORMAL : bon compromis performance/durabilité
PRAGMA synchronous = NORMAL;


-- ============================================================================
-- DOMAINE 1 : MITRE & SIGNATURES
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 1 : mitre_tactics
-- ----------------------------------------------------------------------------
-- Les 14 tactiques officielles MITRE ATT&CK Enterprise.
-- Référentiel statique alimenté par mitre_tactics.sql
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitre_tactics (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    tactic_id           TEXT    NOT NULL UNIQUE,         -- Ex: "TA0001"
    name                TEXT    NOT NULL,                -- Ex: "Initial Access"
    description         TEXT,
    description_fr      TEXT,
    url                 TEXT,
    display_order       INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mitre_tactics_tactic_id ON mitre_tactics(tactic_id);


-- ----------------------------------------------------------------------------
-- Table 2 : mitre_techniques
-- ----------------------------------------------------------------------------
-- 137 techniques MITRE ATT&CK + sous-techniques.
-- Référentiel statique alimenté par mitre_techniques.sql
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id            TEXT    NOT NULL UNIQUE,         -- Ex: "T1110" ou "T1110.001"
    name                    TEXT    NOT NULL,
    description             TEXT,
    description_fr          TEXT,
    tactic_id               INTEGER NOT NULL,
    parent_technique_id     INTEGER,
    platforms               TEXT,                            -- JSON: ["Linux","Windows"]
    data_sources            TEXT,                            -- JSON
    detection_notes         TEXT,
    mitigation_notes        TEXT,
    url                     TEXT,
    is_subtechnique         INTEGER NOT NULL DEFAULT 0 CHECK(is_subtechnique IN (0,1)),
    created_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tactic_id)             REFERENCES mitre_tactics(id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_technique_id)   REFERENCES mitre_techniques(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mitre_techniques_technique_id   ON mitre_techniques(technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_techniques_tactic_id      ON mitre_techniques(tactic_id);
CREATE INDEX IF NOT EXISTS idx_mitre_techniques_parent         ON mitre_techniques(parent_technique_id);


-- ----------------------------------------------------------------------------
-- Table 3 : signature_categories
-- ----------------------------------------------------------------------------
-- Les 10 catégories métier de classification des attaques.
-- Référentiel statique alimenté par categories.sql
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signature_categories (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    code                TEXT    NOT NULL UNIQUE,         -- Ex: "BRUTE_FORCE"
    name                TEXT    NOT NULL,                -- Ex: "Brute Force / Authentification"
    description         TEXT,
    description_fr      TEXT,
    icon                TEXT,                            -- Pour le dashboard
    color_hex           TEXT,                            -- Pour graphiques
    display_order       INTEGER NOT NULL DEFAULT 0,
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_categories_code ON signature_categories(code);


-- ----------------------------------------------------------------------------
-- Table 4 : signatures (TABLE CENTRALE)
-- ----------------------------------------------------------------------------
-- 380 signatures de détection : 190 Snort + 190 Wazuh.
-- L'ID est le rule_id natif (Snort SID ou Wazuh rule_id) pour matching direct.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signatures (
    id                      INTEGER PRIMARY KEY,         -- = rule_id natif (PAS d'AUTOINCREMENT)
    source                  TEXT    NOT NULL CHECK(source IN ('WAZUH','SNORT')),
    category_id             INTEGER NOT NULL,
    technique_id            INTEGER,                     -- NULL si pas de mapping MITRE direct

    -- Identification & description (pédagogique)
    name                    TEXT    NOT NULL,
    description             TEXT    NOT NULL,            -- EN, pédagogique
    description_fr          TEXT    NOT NULL,            -- FR, pédagogique

    -- Classification
    severity                TEXT    NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    confidence              INTEGER NOT NULL DEFAULT 70 CHECK(confidence BETWEEN 0 AND 100),

    -- Action recommandée
    recommended_action      TEXT    NOT NULL DEFAULT 'ALERT' CHECK(recommended_action IN ('ALERT','BLOCK','MONITOR','HONEYPOT','QUARANTINE')),
    remediation_fr          TEXT    NOT NULL,            -- FR, structurée et actionnable

    -- Préparation IA (pour copilote dashboard et enrichissement futur)
    ai_context_keywords     TEXT,                        -- JSON: mots-clés contextuels

    -- Statut
    is_active               INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    is_noisy                INTEGER NOT NULL DEFAULT 0 CHECK(is_noisy IN (0,1)),  -- Pré-tagging bruit

    -- Métadonnées
    tags                    TEXT,                        -- JSON array
    metadata                TEXT,                        -- JSON pour extensions

    -- Audit
    created_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at              TEXT,                        -- Soft delete

    FOREIGN KEY (category_id)  REFERENCES signature_categories(id) ON DELETE RESTRICT,
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id)    ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_signatures_source        ON signatures(source);
CREATE INDEX IF NOT EXISTS idx_signatures_category      ON signatures(category_id);
CREATE INDEX IF NOT EXISTS idx_signatures_technique     ON signatures(technique_id);
CREATE INDEX IF NOT EXISTS idx_signatures_severity      ON signatures(severity);
CREATE INDEX IF NOT EXISTS idx_signatures_active        ON signatures(is_active);
CREATE INDEX IF NOT EXISTS idx_signatures_action        ON signatures(recommended_action);
CREATE INDEX IF NOT EXISTS idx_signatures_noisy         ON signatures(is_noisy);

CREATE TRIGGER IF NOT EXISTS trg_signatures_updated
    AFTER UPDATE ON signatures FOR EACH ROW
BEGIN
    UPDATE signatures SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;


-- ============================================================================
-- DOMAINE 2 : ÉVÉNEMENTS & DÉTECTION
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 5 : raw_events
-- ----------------------------------------------------------------------------
-- Logs bruts capturés par Module 1 (Snort/Wazuh) avant corrélation.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS raw_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uuid          TEXT    NOT NULL UNIQUE,

    source_system       TEXT    NOT NULL CHECK(source_system IN ('SNORT','WAZUH','SYSLOG','HONEYPOT','AGENT','OTHER')),
    source_rule_id      INTEGER,                         -- ID natif Snort/Wazuh

    event_timestamp     TEXT    NOT NULL,
    received_at         TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    src_ip              TEXT,
    src_port            INTEGER,
    dst_ip              TEXT,
    dst_port            INTEGER,
    protocol            TEXT,

    message             TEXT    NOT NULL,
    raw_payload         TEXT,                            -- JSON

    asset_id            INTEGER,
    matched_signature_id INTEGER,

    processed           INTEGER NOT NULL DEFAULT 0 CHECK(processed IN (0,1)),
    processed_at        TEXT,

    -- État de filtrage (faux positif)
    filtered            INTEGER NOT NULL DEFAULT 0 CHECK(filtered IN (0,1)),
    filter_id           INTEGER,                         -- Quel filtre a matché

    metadata            TEXT,                            -- JSON

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (asset_id)              REFERENCES assets(id)         ON DELETE SET NULL,
    FOREIGN KEY (matched_signature_id)  REFERENCES signatures(id)     ON DELETE SET NULL,
    FOREIGN KEY (filter_id)             REFERENCES alert_filters(id)  ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_raw_events_uuid          ON raw_events(event_uuid);
CREATE INDEX IF NOT EXISTS idx_raw_events_timestamp     ON raw_events(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_raw_events_src_ip        ON raw_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_raw_events_processed     ON raw_events(processed);
CREATE INDEX IF NOT EXISTS idx_raw_events_signature     ON raw_events(matched_signature_id);
CREATE INDEX IF NOT EXISTS idx_raw_events_filtered      ON raw_events(filtered);


-- ----------------------------------------------------------------------------
-- Table 6 : alerts
-- ----------------------------------------------------------------------------
-- Alertes corrélées et enrichies par l'agent (Module 3).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_uuid          TEXT    NOT NULL UNIQUE,

    signature_id        INTEGER NOT NULL,
    severity            TEXT    NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    confidence          INTEGER NOT NULL DEFAULT 70 CHECK(confidence BETWEEN 0 AND 100),

    title               TEXT    NOT NULL,
    description         TEXT,
    src_ip              TEXT,
    dst_ip              TEXT,
    asset_id            INTEGER,

    event_count         INTEGER NOT NULL DEFAULT 1,
    first_seen          TEXT    NOT NULL,
    last_seen           TEXT    NOT NULL,

    -- Workflow (avec FALSE_POSITIVE pour gestion faux positifs)
    status              TEXT    NOT NULL DEFAULT 'NEW' CHECK(status IN ('NEW','ACKNOWLEDGED','INVESTIGATING','RESOLVED','FALSE_POSITIVE','IGNORED')),
    incident_id         INTEGER,
    assigned_to         INTEGER,
    resolved_at         TEXT,
    resolution_notes    TEXT,

    enriched_data       TEXT,                            -- JSON
    tags                TEXT,                            -- JSON array
    metadata            TEXT,                            -- JSON

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (signature_id)  REFERENCES signatures(id)  ON DELETE RESTRICT,
    FOREIGN KEY (asset_id)      REFERENCES assets(id)      ON DELETE SET NULL,
    FOREIGN KEY (incident_id)   REFERENCES incidents(id)   ON DELETE SET NULL,
    FOREIGN KEY (assigned_to)   REFERENCES users(id)       ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_uuid          ON alerts(alert_uuid);
CREATE INDEX IF NOT EXISTS idx_alerts_signature     ON alerts(signature_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity      ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status        ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip        ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_first_seen    ON alerts(first_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_incident      ON alerts(incident_id);

CREATE TRIGGER IF NOT EXISTS trg_alerts_updated
    AFTER UPDATE ON alerts FOR EACH ROW
BEGIN
    UPDATE alerts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;


-- ----------------------------------------------------------------------------
-- Table 7 : incidents
-- ----------------------------------------------------------------------------
-- Regroupement d'alertes corrélées en un incident de sécurité.
-- Workflow NIST 800-61 : OPEN → INVESTIGATING → CONTAINED → ERADICATED → RECOVERED → CLOSED
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_uuid       TEXT    NOT NULL UNIQUE,
    reference           TEXT    NOT NULL UNIQUE,         -- Ex: "INC-2026-04-0001"

    title               TEXT    NOT NULL,
    description         TEXT,
    severity            TEXT    NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    status              TEXT    NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','INVESTIGATING','CONTAINED','ERADICATED','RECOVERED','CLOSED')),

    created_by          INTEGER,
    assigned_to         INTEGER,
    is_automated        INTEGER NOT NULL DEFAULT 0 CHECK(is_automated IN (0,1)),

    -- Timing NIST 800-61
    detected_at         TEXT    NOT NULL,
    contained_at        TEXT,
    eradicated_at       TEXT,
    recovered_at        TEXT,
    closed_at           TEXT,

    attack_vector       TEXT,
    impact              TEXT,
    lessons_learned     TEXT,

    metadata            TEXT,

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by)    REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (assigned_to)   REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_uuid       ON incidents(incident_uuid);
CREATE INDEX IF NOT EXISTS idx_incidents_reference  ON incidents(reference);
CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity   ON incidents(severity);

CREATE TRIGGER IF NOT EXISTS trg_incidents_updated
    AFTER UPDATE ON incidents FOR EACH ROW
BEGIN
    UPDATE incidents SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;


-- ============================================================================
-- DOMAINE 3 : GESTION DES FAUX POSITIFS
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 8 : alert_filters
-- ----------------------------------------------------------------------------
-- Filtres et exclusions pour gérer les faux positifs.
-- Permet à l'admin de définir des règles d'exclusion contextuelles.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_filters (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    filter_uuid         TEXT    NOT NULL UNIQUE,
    name                TEXT    NOT NULL,

    -- Conditions de filtrage (toutes optionnelles, ET logique)
    signature_id        INTEGER,                         -- Filtrer par règle
    src_ip              TEXT,                            -- Filtrer par IP source
    src_ip_pattern      TEXT,                            -- Pattern regex IP
    dst_ip              TEXT,                            -- Filtrer par IP destination
    asset_id            INTEGER,                         -- Filtrer par asset
    user_pattern        TEXT,                            -- Pattern utilisateur (regex)
    time_window         TEXT,                            -- Plage horaire (ex: "08:00-18:00")
    days_of_week        TEXT,                            -- JSON: ["MON","TUE","WED"]

    -- Comportement
    action              TEXT    NOT NULL DEFAULT 'IGNORE' CHECK(action IN ('IGNORE','DOWNGRADE','NOTIFY_ONLY')),
    downgrade_to        TEXT    CHECK(downgrade_to IN ('INFO','LOW','MEDIUM','HIGH')),

    -- Origine du filtre
    filter_type         TEXT    NOT NULL DEFAULT 'MANUAL' CHECK(filter_type IN ('MANUAL','AUTO_NOISE','PRE_TAGGED','SUGGESTED_AI')),

    -- Métadonnées
    reason              TEXT    NOT NULL,
    created_by          INTEGER,
    expires_at          TEXT,                            -- NULL = permanent
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),

    -- Stats
    hit_count           INTEGER NOT NULL DEFAULT 0,
    last_hit_at         TEXT,

    metadata            TEXT,                            -- JSON

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (signature_id)  REFERENCES signatures(id)   ON DELETE CASCADE,
    FOREIGN KEY (asset_id)      REFERENCES assets(id)       ON DELETE CASCADE,
    FOREIGN KEY (created_by)    REFERENCES users(id)        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_filters_uuid         ON alert_filters(filter_uuid);
CREATE INDEX IF NOT EXISTS idx_filters_signature    ON alert_filters(signature_id);
CREATE INDEX IF NOT EXISTS idx_filters_active       ON alert_filters(is_active);
CREATE INDEX IF NOT EXISTS idx_filters_expires      ON alert_filters(expires_at);
CREATE INDEX IF NOT EXISTS idx_filters_type         ON alert_filters(filter_type);

CREATE TRIGGER IF NOT EXISTS trg_filters_updated
    AFTER UPDATE ON alert_filters FOR EACH ROW
BEGIN
    UPDATE alert_filters SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;



-- ============================================================================
-- DOMAINE 4 : ACTIFS & CONTEXTE
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 9 : assets
-- ----------------------------------------------------------------------------
-- Inventaire des équipements surveillés (incluant agents Wazuh).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assets (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_uuid              TEXT    NOT NULL UNIQUE,

    -- Identification
    hostname                TEXT    NOT NULL,
    ip_address              TEXT    NOT NULL,
    mac_address             TEXT,

    -- Classification
    asset_type              TEXT    NOT NULL CHECK(asset_type IN ('SERVER','WORKSTATION','LAPTOP','ROUTER','FIREWALL','SWITCH','IOT','MOBILE','VM','CONTAINER','OTHER')),
    criticality             TEXT    NOT NULL DEFAULT 'MEDIUM' CHECK(criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    os                      TEXT,
    os_version              TEXT,

    -- Organisation
    owner                   TEXT,
    location                TEXT,
    environment             TEXT    DEFAULT 'PRODUCTION' CHECK(environment IN ('PRODUCTION','STAGING','DEV','TEST')),

    -- Wazuh agent (intégration)
    wazuh_agent_id          TEXT,                            -- ID Wazuh assigné (ex: "002")
    wazuh_agent_status      TEXT    CHECK(wazuh_agent_status IN ('PENDING','ACTIVE','DISCONNECTED','REMOVED','NEVER_CONNECTED')),
    wazuh_agent_key         TEXT,                            -- Clé d'enrôlement (chiffrée)
    wazuh_last_keepalive    TEXT,                            -- Dernier ping reçu

    -- Statut
    is_active               INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    last_seen               TEXT,

    -- Métadonnées
    tags                    TEXT,                            -- JSON
    notes                   TEXT,
    metadata                TEXT,                            -- JSON

    created_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at              TEXT
);

CREATE INDEX IF NOT EXISTS idx_assets_uuid          ON assets(asset_uuid);
CREATE INDEX IF NOT EXISTS idx_assets_hostname      ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip            ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_type          ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality   ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_wazuh_id      ON assets(wazuh_agent_id);
CREATE INDEX IF NOT EXISTS idx_assets_wazuh_status  ON assets(wazuh_agent_status);

CREATE TRIGGER IF NOT EXISTS trg_assets_updated
    AFTER UPDATE ON assets FOR EACH ROW
BEGIN
    UPDATE assets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;


-- ----------------------------------------------------------------------------
-- Table 10 : ip_reputation
-- ----------------------------------------------------------------------------
-- Score de réputation des IPs avec historique.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ip_reputation (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address          TEXT    NOT NULL UNIQUE,

    reputation_score    INTEGER NOT NULL DEFAULT 50 CHECK(reputation_score BETWEEN 0 AND 100),
    risk_level          TEXT    NOT NULL DEFAULT 'MEDIUM' CHECK(risk_level IN ('CLEAN','LOW','MEDIUM','HIGH','MALICIOUS')),

    categories          TEXT,                            -- JSON: ["scanner","spam"]
    sources             TEXT,                            -- JSON: ["abuseipdb"]
    last_source_update  TEXT,

    alert_count         INTEGER NOT NULL DEFAULT 0,
    last_seen_alert     TEXT,
    first_seen          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    country_code        TEXT,                            -- Ex: "CM", "NG"
    asn                 INTEGER,
    asn_name            TEXT,

    notes               TEXT,
    metadata            TEXT,                            -- JSON

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_rep_address       ON ip_reputation(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_rep_score         ON ip_reputation(reputation_score);
CREATE INDEX IF NOT EXISTS idx_ip_rep_risk          ON ip_reputation(risk_level);
CREATE INDEX IF NOT EXISTS idx_ip_rep_country       ON ip_reputation(country_code);

CREATE TRIGGER IF NOT EXISTS trg_ip_rep_updated
    AFTER UPDATE ON ip_reputation FOR EACH ROW
BEGIN
    UPDATE ip_reputation SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;


-- ----------------------------------------------------------------------------
-- Table 11 : threat_intel
-- ----------------------------------------------------------------------------
-- Indicateurs de compromission (IoCs) externes.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type            TEXT    NOT NULL CHECK(ioc_type IN ('ip','domain','url','hash_md5','hash_sha256','email','file_path')),
    value               TEXT    NOT NULL,
    source              TEXT    NOT NULL,                -- 'virustotal', 'abuseipdb'
    confidence          INTEGER CHECK(confidence BETWEEN 0 AND 100),
    severity            TEXT    CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),

    description         TEXT,
    description_fr      TEXT,
    tags                TEXT,                            -- JSON

    fetched_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TEXT,
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),

    metadata            TEXT,                            -- JSON

    UNIQUE (ioc_type, value, source)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_value       ON threat_intel(value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type        ON threat_intel(ioc_type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_active      ON threat_intel(is_active);


-- ============================================================================
-- DOMAINE 5 : RÉPONSE ACTIVE
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 12 : blocked_ips
-- ----------------------------------------------------------------------------
-- Liste des IPs bloquées via iptables par l'agent ou un admin.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocked_ips (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address          TEXT    NOT NULL,

    alert_id            INTEGER,
    signature_id        INTEGER,
    reason              TEXT    NOT NULL,
    severity            TEXT    CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),

    blocked_by          TEXT    NOT NULL CHECK(blocked_by IN ('AGENT','MANUAL','THREAT_INTEL','HONEYPOT','AI_RECOMMENDED')),
    blocked_by_user     INTEGER,

    blocked_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TEXT,                            -- NULL = permanent
    unblocked_at        TEXT,
    unblocked_by        INTEGER,
    unblock_reason      TEXT,

    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    iptables_rule       TEXT,                            -- Règle exacte pour rollback

    metadata            TEXT,

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (alert_id)          REFERENCES alerts(id)     ON DELETE SET NULL,
    FOREIGN KEY (signature_id)      REFERENCES signatures(id) ON DELETE SET NULL,
    FOREIGN KEY (blocked_by_user)   REFERENCES users(id)      ON DELETE SET NULL,
    FOREIGN KEY (unblocked_by)      REFERENCES users(id)      ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip       ON blocked_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active   ON blocked_ips(is_active);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires  ON blocked_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_alert    ON blocked_ips(alert_id);


-- ----------------------------------------------------------------------------
-- Table 13 : honeypot_hits
-- ----------------------------------------------------------------------------
-- Tentatives capturées par les honeypots SSH/HTTP/MySQL du Module 3.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS honeypot_hits (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_uuid            TEXT    NOT NULL UNIQUE,

    honeypot_type       TEXT    NOT NULL CHECK(honeypot_type IN ('SSH','HTTP','MYSQL','FTP','TELNET','CUSTOM')),
    honeypot_port       INTEGER NOT NULL,

    src_ip              TEXT    NOT NULL,
    src_port            INTEGER,
    user_agent          TEXT,

    username_attempted  TEXT,
    password_attempted  TEXT,
    command_executed    TEXT,
    http_path           TEXT,
    http_method         TEXT,

    payload             TEXT,
    payload_size        INTEGER,

    session_duration_sec INTEGER,
    hit_at              TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    tactic_suspected    TEXT,
    linked_alert_id     INTEGER,

    metadata            TEXT,                            -- JSON

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (linked_alert_id) REFERENCES alerts(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_honeypot_hits_uuid   ON honeypot_hits(hit_uuid);
CREATE INDEX IF NOT EXISTS idx_honeypot_hits_type   ON honeypot_hits(honeypot_type);
CREATE INDEX IF NOT EXISTS idx_honeypot_hits_src_ip ON honeypot_hits(src_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_hits_at     ON honeypot_hits(hit_at);


-- ============================================================================
-- DOMAINE 6 : UTILISATEURS
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 14 : roles
-- ----------------------------------------------------------------------------
-- Rôles RBAC : admin, analyst, operator, viewer
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    code                TEXT    NOT NULL UNIQUE,         -- Ex: "ADMIN", "ANALYST"
    name                TEXT    NOT NULL,
    description         TEXT,
    description_fr      TEXT,

    permissions         TEXT    NOT NULL,                -- JSON

    is_system           INTEGER NOT NULL DEFAULT 0 CHECK(is_system IN (0,1)),
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_roles_code ON roles(code);


-- ----------------------------------------------------------------------------
-- Table 15 : users
-- ----------------------------------------------------------------------------
-- Utilisateurs du SIEM (admin, analystes, etc.)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_uuid           TEXT    NOT NULL UNIQUE,

    email               TEXT    NOT NULL UNIQUE,
    first_name          TEXT,
    last_name           TEXT,
    phone               TEXT,

    password_hash       TEXT    NOT NULL,                -- argon2id
    password_changed_at TEXT,
    must_change_pwd     INTEGER NOT NULL DEFAULT 1 CHECK(must_change_pwd IN (0,1)),

    is_active           INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    is_locked           INTEGER NOT NULL DEFAULT 0 CHECK(is_locked IN (0,1)),
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,

    role_id             INTEGER NOT NULL,

    organization        TEXT,
    department          TEXT,

    language            TEXT    NOT NULL DEFAULT 'fr' CHECK(language IN ('fr','en')),
    timezone            TEXT    NOT NULL DEFAULT 'Africa/Abidjan',

    last_login_at       TEXT,
    last_login_ip       TEXT,

    metadata            TEXT,                            -- JSON
    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TEXT,

    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_users_uuid       ON users(user_uuid);
CREATE INDEX IF NOT EXISTS idx_users_email      ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role       ON users(role_id);
CREATE INDEX IF NOT EXISTS idx_users_is_active  ON users(is_active);

CREATE TRIGGER IF NOT EXISTS trg_users_updated
    AFTER UPDATE ON users FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;


-- ----------------------------------------------------------------------------
-- Table 16 : user_sessions
-- ----------------------------------------------------------------------------
-- Sessions actives (tokens JWT pour Dashboard).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_sessions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_uuid        TEXT    NOT NULL UNIQUE,
    user_id             INTEGER NOT NULL,

    token               TEXT    NOT NULL UNIQUE,
    refresh_token       TEXT    UNIQUE,
    ip_address          TEXT,
    user_agent          TEXT,
    device_type         TEXT,                            -- 'web', 'api'

    expires_at          TEXT    NOT NULL,
    revoked_at          TEXT,
    revoked_reason      TEXT,

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at        TEXT,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_uuid    ON user_sessions(session_uuid);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token   ON user_sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);


-- ============================================================================
-- DOMAINE 7 : COMMUNICATIONS
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 17 : notifications
-- ----------------------------------------------------------------------------
-- Notifications in-app pour le dashboard.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    notification_uuid   TEXT    NOT NULL UNIQUE,
    user_id             INTEGER NOT NULL,

    title               TEXT    NOT NULL,
    message             TEXT    NOT NULL,
    severity            TEXT    NOT NULL CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    notification_type   TEXT    NOT NULL CHECK(notification_type IN ('ALERT','INCIDENT','SYSTEM','AI_INSIGHT','REPORT_READY','OTHER')),

    related_alert_id    INTEGER,
    related_incident_id INTEGER,
    action_url          TEXT,

    is_read             INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
    read_at             TEXT,
    is_dismissed        INTEGER NOT NULL DEFAULT 0 CHECK(is_dismissed IN (0,1)),

    metadata            TEXT,

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id)               REFERENCES users(id)      ON DELETE CASCADE,
    FOREIGN KEY (related_alert_id)      REFERENCES alerts(id)     ON DELETE SET NULL,
    FOREIGN KEY (related_incident_id)   REFERENCES incidents(id)  ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_notif_user       ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notif_read       ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notif_created    ON notifications(created_at);


-- ----------------------------------------------------------------------------
-- Table 18 : email_logs
-- ----------------------------------------------------------------------------
-- Historique des emails envoyés par l'agent et le dashboard.
-- Anti-spam interne via dedup_key.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS email_logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    email_uuid          TEXT    NOT NULL UNIQUE,

    recipient_email     TEXT    NOT NULL,
    recipient_user_id   INTEGER,
    cc_emails           TEXT,                            -- JSON array

    subject             TEXT    NOT NULL,
    body_html           TEXT,
    body_text           TEXT,

    email_type          TEXT    NOT NULL CHECK(email_type IN (
        'CRITICAL_ALERT',
        'INCIDENT_DIGEST',
        'DAILY_REPORT',
        'WEEKLY_REPORT',
        'PASSWORD_RESET',
        'WELCOME',
        'AI_INSIGHT',
        'NOISE_ALERT',
        'OTHER'
    )),
    priority            TEXT    NOT NULL DEFAULT 'NORMAL' CHECK(priority IN ('LOW','NORMAL','HIGH','URGENT')),

    related_alert_id    INTEGER,
    related_incident_id INTEGER,

    status              TEXT    NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','SENT','DELIVERED','FAILED')),
    error_message       TEXT,

    -- Anti-spam interne
    dedup_key           TEXT,                            -- Hash pour éviter doublons
    retry_count         INTEGER NOT NULL DEFAULT 0,

    smtp_message_id     TEXT,
    smtp_provider       TEXT,                            -- 'postfix_local', 'gmail', 'sendgrid'

    queued_at           TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at             TEXT,
    delivered_at        TEXT,

    metadata            TEXT,

    FOREIGN KEY (recipient_user_id)   REFERENCES users(id)      ON DELETE SET NULL,
    FOREIGN KEY (related_alert_id)    REFERENCES alerts(id)     ON DELETE SET NULL,
    FOREIGN KEY (related_incident_id) REFERENCES incidents(id)  ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_email_logs_recipient     ON email_logs(recipient_email);
CREATE INDEX IF NOT EXISTS idx_email_logs_type          ON email_logs(email_type);
CREATE INDEX IF NOT EXISTS idx_email_logs_status        ON email_logs(status);
CREATE INDEX IF NOT EXISTS idx_email_logs_dedup         ON email_logs(dedup_key);
CREATE INDEX IF NOT EXISTS idx_email_logs_alert         ON email_logs(related_alert_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_queued        ON email_logs(queued_at);


-- ============================================================================
-- DOMAINE 8 : GOUVERNANCE
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 19 : audit_log
-- ----------------------------------------------------------------------------
-- Journal d'audit complet (toutes actions sensibles).
-- Conforme RGPD/conformité.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_uuid          TEXT    NOT NULL UNIQUE,

    user_id             INTEGER,
    user_email          TEXT,                            -- Cache au cas où user supprimé
    ip_address          TEXT,
    user_agent          TEXT,

    action              TEXT    NOT NULL,
    action_category     TEXT    NOT NULL CHECK(action_category IN ('AUTH','CONFIG','ALERT','INCIDENT','USER','ASSET','BLOCK','DATA_EXPORT','AI','FILTER','OTHER')),

    target_table        TEXT,
    target_id           INTEGER,
    target_description  TEXT,

    old_value           TEXT,                            -- JSON
    new_value           TEXT,                            -- JSON
    details             TEXT,

    status              TEXT    NOT NULL DEFAULT 'SUCCESS' CHECK(status IN ('SUCCESS','FAILURE','PARTIAL')),
    error_message       TEXT,

    performed_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    duration_ms         INTEGER,

    metadata            TEXT,

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user       ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action     ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_category   ON audit_log(action_category);
CREATE INDEX IF NOT EXISTS idx_audit_log_target     ON audit_log(target_table, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_performed  ON audit_log(performed_at);


-- ----------------------------------------------------------------------------
-- Table 20 : settings
-- ----------------------------------------------------------------------------
-- Paramètres globaux (clé/valeur).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    key                 TEXT    NOT NULL UNIQUE,
    value               TEXT,
    value_type          TEXT    NOT NULL DEFAULT 'string' CHECK(value_type IN ('string','int','bool','json','secret')),

    description         TEXT,
    description_fr      TEXT,
    category            TEXT,                            -- 'smtp', 'ai', 'detection', etc.

    is_secret           INTEGER NOT NULL DEFAULT 0 CHECK(is_secret IN (0,1)),
    is_public           INTEGER NOT NULL DEFAULT 0 CHECK(is_public IN (0,1)),
    is_editable         INTEGER NOT NULL DEFAULT 1 CHECK(is_editable IN (0,1)),

    updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by          INTEGER,

    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_settings_key      ON settings(key);
CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category);


-- ----------------------------------------------------------------------------
-- Table 21 : reports
-- ----------------------------------------------------------------------------
-- Historique des rapports PDF/Excel générés.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    report_uuid         TEXT    NOT NULL UNIQUE,

    type                TEXT    NOT NULL CHECK(type IN ('DAILY','WEEKLY','MONTHLY','INCIDENT','CUSTOM','COMPLIANCE')),
    title               TEXT    NOT NULL,
    format              TEXT    NOT NULL CHECK(format IN ('PDF','EXCEL','CSV','JSON')),

    file_path           TEXT    NOT NULL,
    file_size           INTEGER,
    file_hash           TEXT,                            -- SHA-256

    period_start        TEXT,
    period_end          TEXT,

    generated_by        INTEGER,
    generated_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    generation_time_ms  INTEGER,

    download_count      INTEGER NOT NULL DEFAULT 0,
    last_downloaded_at  TEXT,

    status              TEXT    NOT NULL DEFAULT 'READY' CHECK(status IN ('GENERATING','READY','FAILED','EXPIRED','DELETED')),
    error_message       TEXT,

    metadata            TEXT,

    FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_type         ON reports(type);
CREATE INDEX IF NOT EXISTS idx_reports_generated    ON reports(generated_at);
CREATE INDEX IF NOT EXISTS idx_reports_status       ON reports(status);


-- ============================================================================
-- DOMAINE 9 : INTELLIGENCE ARTIFICIELLE
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Table 22 : ai_explanations
-- ----------------------------------------------------------------------------
-- Cache des explications IA pour les alertes (Ollama local en v1).
-- Évite de re-payer les tokens si la même alerte est consultée plusieurs fois.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ai_explanations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    explanation_uuid    TEXT    NOT NULL UNIQUE,

    -- Cible
    alert_id            INTEGER,
    signature_id        INTEGER,                         -- Si explication générique sur signature

    -- Question/contexte fourni à l'IA
    question            TEXT,                            -- Question de l'utilisateur (si interactive)
    context_summary     TEXT,                            -- Résumé du contexte fourni à l'IA

    -- Réponse IA
    explanation_fr      TEXT    NOT NULL,
    explanation_en      TEXT,

    -- Méta IA
    ai_provider         TEXT    NOT NULL,                -- 'ollama', 'claude', 'openai'
    ai_model            TEXT    NOT NULL,                -- 'llama3.2:3b', 'claude-opus-4-7'
    tokens_used         INTEGER,
    response_time_ms    INTEGER,

    -- Feedback utilisateur
    rating              INTEGER CHECK(rating IN (-1, 0, 1)),  -- -1 mauvais, 0 neutre, 1 bon
    feedback_comment    TEXT,
    rated_by            INTEGER,
    rated_at            TEXT,

    -- Cache
    is_cached           INTEGER NOT NULL DEFAULT 1 CHECK(is_cached IN (0,1)),
    cache_hits          INTEGER NOT NULL DEFAULT 0,
    last_used_at        TEXT,

    metadata            TEXT,

    created_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (alert_id)      REFERENCES alerts(id)     ON DELETE CASCADE,
    FOREIGN KEY (signature_id)  REFERENCES signatures(id) ON DELETE CASCADE,
    FOREIGN KEY (rated_by)      REFERENCES users(id)      ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_expl_alert        ON ai_explanations(alert_id);
CREATE INDEX IF NOT EXISTS idx_ai_expl_signature    ON ai_explanations(signature_id);
CREATE INDEX IF NOT EXISTS idx_ai_expl_provider     ON ai_explanations(ai_provider);
CREATE INDEX IF NOT EXISTS idx_ai_expl_created      ON ai_explanations(created_at);


-- ============================================================================
-- TRIGGERS POUR LA GESTION DES FAUX POSITIFS (apprentissage automatique)
-- ============================================================================

-- Diminue la confidence quand une alerte est marquée FALSE_POSITIVE
CREATE TRIGGER IF NOT EXISTS trg_decrease_confidence_on_fp
AFTER UPDATE OF status ON alerts
WHEN NEW.status = 'FALSE_POSITIVE' AND (OLD.status IS NULL OR OLD.status != 'FALSE_POSITIVE')
BEGIN
    UPDATE signatures
    SET confidence = MAX(50, confidence - 1)
    WHERE id = NEW.signature_id;
END;

-- Augmente la confidence quand une alerte est confirmée RESOLVED
CREATE TRIGGER IF NOT EXISTS trg_increase_confidence_on_resolved
AFTER UPDATE OF status ON alerts
WHEN NEW.status = 'RESOLVED' AND (OLD.status IS NULL OR OLD.status != 'RESOLVED')
BEGIN
    UPDATE signatures
    SET confidence = MIN(100, confidence + 1)
    WHERE id = NEW.signature_id;
END;


-- ============================================================================
-- VUES UTILES POUR LE DASHBOARD ET L'AGENT
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Vue 1 : v_alerts_enriched
-- Alertes enrichies avec contexte complet (signature, MITRE, asset, IP rep).
-- ----------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS v_alerts_enriched AS
SELECT
    a.id,
    a.alert_uuid,
    a.first_seen,
    a.last_seen,
    a.severity,
    a.confidence,
    a.status,
    a.title,
    a.description,
    a.src_ip,
    a.dst_ip,
    a.event_count,

    -- Signature
    s.id              AS signature_id,
    s.name            AS signature_name,
    s.description_fr  AS signature_description,
    s.remediation_fr  AS signature_remediation,
    s.recommended_action,
    s.source          AS signature_source,
    s.is_noisy        AS signature_is_noisy,

    -- Catégorie
    sc.code           AS category_code,
    sc.name           AS category_name,
    sc.color_hex      AS category_color,

    -- MITRE
    mt.technique_id   AS mitre_technique_id,
    mt.name           AS mitre_technique_name,
    mtac.tactic_id    AS mitre_tactic_id,
    mtac.name         AS mitre_tactic_name,

    -- Asset
    ast.hostname      AS asset_hostname,
    ast.criticality   AS asset_criticality,

    -- IP réputation
    ipr.reputation_score,
    ipr.risk_level    AS ip_risk_level,
    ipr.country_code  AS src_country,

    -- Workflow
    a.incident_id,
    a.assigned_to,
    u.email           AS assignee_email,
    a.created_at
FROM alerts a
LEFT JOIN signatures s              ON a.signature_id = s.id
LEFT JOIN signature_categories sc   ON s.category_id = sc.id
LEFT JOIN mitre_techniques mt       ON s.technique_id = mt.id
LEFT JOIN mitre_tactics mtac        ON mt.tactic_id = mtac.id
LEFT JOIN assets ast                ON a.asset_id = ast.id
LEFT JOIN ip_reputation ipr         ON a.src_ip = ipr.ip_address
LEFT JOIN users u                   ON a.assigned_to = u.id;


-- ----------------------------------------------------------------------------
-- Vue 2 : v_dashboard_metrics
-- Métriques principales pour le dashboard (KPIs).
-- ----------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS v_dashboard_metrics AS
SELECT
    (SELECT COUNT(*) FROM alerts WHERE status = 'NEW')                                                              AS new_alerts,
    (SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status NOT IN ('RESOLVED','FALSE_POSITIVE'))       AS critical_open,
    (SELECT COUNT(*) FROM incidents WHERE status NOT IN ('CLOSED'))                                                 AS open_incidents,
    (SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1)                                                          AS active_blocks,
    (SELECT COUNT(*) FROM alert_filters WHERE is_active = 1)                                                        AS active_filters,
    (SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now','-24 hours'))                                   AS alerts_24h,
    (SELECT COUNT(*) FROM alerts WHERE status = 'FALSE_POSITIVE' AND created_at >= datetime('now','-24 hours'))     AS false_positives_24h,
    (SELECT COUNT(*) FROM honeypot_hits WHERE hit_at >= datetime('now','-24 hours'))                                AS honeypot_24h,
    (SELECT COUNT(*) FROM users WHERE is_active = 1)                                                                AS active_users,
    (SELECT COUNT(*) FROM assets WHERE is_active = 1)                                                               AS monitored_assets,
    (SELECT COUNT(*) FROM assets WHERE wazuh_agent_status = 'ACTIVE')                                               AS active_wazuh_agents;


-- ----------------------------------------------------------------------------
-- Vue 3 : v_top_attackers_week
-- Top 20 des IPs attaquantes sur les 7 derniers jours.
-- ----------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS v_top_attackers_week AS
SELECT
    a.src_ip,
    COUNT(*)                                AS alert_count,
    MAX(a.severity)                         AS max_severity,
    MIN(a.first_seen)                       AS first_seen,
    MAX(a.last_seen)                        AS last_seen,
    COUNT(DISTINCT a.signature_id)          AS distinct_attacks,
    ipr.country_code,
    ipr.reputation_score,
    ipr.risk_level,
    (SELECT COUNT(*) FROM blocked_ips bi WHERE bi.ip_address = a.src_ip AND bi.is_active = 1) AS is_blocked
FROM alerts a
LEFT JOIN ip_reputation ipr ON a.src_ip = ipr.ip_address
WHERE a.created_at >= datetime('now', '-7 days')
  AND a.src_ip IS NOT NULL
GROUP BY a.src_ip
ORDER BY alert_count DESC
LIMIT 20;


-- ============================================================================
-- FIN DU SCHÉMA
-- 22 tables, 3 vues, ~12 triggers, ~95 index
-- ============================================================================

