-- SIEM Africa - Module 2 : Database schema
-- 14 tables + 2 views
-- Target: SQLite 3.x
-- Rules: no PRAGMA journal_mode = WAL ; file is chmod 664 owned by siem-africa:siem-africa

PRAGMA foreign_keys = ON;

-- ============================================================
-- 1. mitre_tactics  (14 tactics — TA#### )
-- ============================================================
CREATE TABLE IF NOT EXISTS mitre_tactics (
    id          TEXT PRIMARY KEY,         -- TA0001, TA0002 ...
    name        TEXT NOT NULL,
    description TEXT,
    url         TEXT
);

-- ============================================================
-- 2. mitre_techniques  (T#### and sub T####.### )
-- ============================================================
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id          TEXT PRIMARY KEY,         -- T1190  or  T1110.001
    tactic_id   TEXT NOT NULL,
    parent_id   TEXT,                      -- NULL for top-level techniques
    name        TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    FOREIGN KEY (tactic_id) REFERENCES mitre_tactics(id),
    FOREIGN KEY (parent_id) REFERENCES mitre_techniques(id)
);

CREATE INDEX IF NOT EXISTS idx_techniques_tactic ON mitre_techniques(tactic_id);

-- ============================================================
-- 3. signatures  (380 detection signatures populated by attacks.sql)
-- ============================================================
CREATE TABLE IF NOT EXISTS signatures (
    id            TEXT PRIMARY KEY,        -- SIG-001 ... SIG-380
    technique_id  TEXT NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT,
    severity      INTEGER NOT NULL DEFAULT 5,    -- 1..10
    keywords      TEXT,                          -- comma-separated match hints
    pattern       TEXT,                          -- optional regex
    fp_likelihood REAL NOT NULL DEFAULT 0.2,     -- 0.0..1.0 baseline false-positive probability
    active        INTEGER NOT NULL DEFAULT 1,    -- 0|1
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id)
);

CREATE INDEX IF NOT EXISTS idx_signatures_technique ON signatures(technique_id);
CREATE INDEX IF NOT EXISTS idx_signatures_active   ON signatures(active);

-- ============================================================
-- 4. agents  (Wazuh agents / monitored hosts)
-- ============================================================
CREATE TABLE IF NOT EXISTS agents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT UNIQUE,              -- Wazuh agent numeric id ("000" for manager)
    name          TEXT NOT NULL,
    ip            TEXT,
    os            TEXT,
    status        TEXT DEFAULT 'active',    -- active|disconnected|never_connected
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen     TIMESTAMP
);

-- ============================================================
-- 5. rules  (Wazuh / Snort rule metadata)
-- ============================================================
CREATE TABLE IF NOT EXISTS rules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id           TEXT NOT NULL,        -- Wazuh rule id (e.g. 5715) or Snort SID
    source            TEXT NOT NULL,         -- wazuh|snort
    level             INTEGER,                -- Wazuh level (0..15)
    description       TEXT,
    groups            TEXT,                   -- comma-separated
    mitre_techniques  TEXT,                   -- comma-separated T####
    UNIQUE (rule_id, source)
);

CREATE INDEX IF NOT EXISTS idx_rules_rule_id ON rules(rule_id);

-- ============================================================
-- 6. alerts  (main event store — fed by the Python agent)
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uid             TEXT UNIQUE,              -- stable id from source (Wazuh id / Snort sid+ts)
    timestamp       TIMESTAMP NOT NULL,
    source          TEXT NOT NULL,             -- wazuh|snort|honeypot
    rule_id         TEXT,
    signature_id    TEXT,
    agent_id        TEXT,
    level           INTEGER DEFAULT 0,
    severity        INTEGER DEFAULT 0,         -- normalized 1..10
    src_ip          TEXT,
    src_port        INTEGER,
    dst_ip          TEXT,
    dst_port        INTEGER,
    protocol        TEXT,
    description     TEXT,
    raw_message     TEXT,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    fp_confidence   REAL DEFAULT 0.0,          -- 0..1 populated by Module 3
    status          TEXT DEFAULT 'new',         -- new|triaged|false_positive|confirmed|blocked
    correlated_with INTEGER,                    -- FK → alerts.id, root of correlation chain
    notified        INTEGER DEFAULT 0,          -- 0|1 (email sent)
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (signature_id)    REFERENCES signatures(id),
    FOREIGN KEY (correlated_with) REFERENCES alerts(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip    ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_technique ON alerts(mitre_technique);

-- ============================================================
-- 7. correlations  (groups of alerts sharing src_ip / tactic within a time window)
-- ============================================================
CREATE TABLE IF NOT EXISTS correlations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    description   TEXT,
    src_ip        TEXT,
    first_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_count   INTEGER DEFAULT 0,
    max_severity  INTEGER DEFAULT 0,
    tactics       TEXT,                       -- comma-separated TA####
    techniques    TEXT,                       -- comma-separated T####
    status        TEXT DEFAULT 'open'         -- open|closed|promoted
);

CREATE INDEX IF NOT EXISTS idx_correlations_src    ON correlations(src_ip);
CREATE INDEX IF NOT EXISTS idx_correlations_status ON correlations(status);

-- ============================================================
-- 8. incidents  (confirmed attacks, typically promoted from a correlation)
-- ============================================================
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    title          TEXT NOT NULL,
    description    TEXT,
    severity       INTEGER NOT NULL,          -- 1..10
    status         TEXT DEFAULT 'open',        -- open|investigating|contained|resolved
    assignee       TEXT,
    correlation_id INTEGER,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at    TIMESTAMP,
    FOREIGN KEY (correlation_id) REFERENCES correlations(id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

-- ============================================================
-- 9. false_positives  (human-validated FP examples → feed FP scorer)
-- ============================================================
CREATE TABLE IF NOT EXISTS false_positives (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id     INTEGER NOT NULL,
    rule_id      TEXT,
    signature_id TEXT,
    src_ip       TEXT,
    reason       TEXT,
    marked_by    TEXT,
    marked_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

CREATE INDEX IF NOT EXISTS idx_fp_rule_id ON false_positives(rule_id);
CREATE INDEX IF NOT EXISTS idx_fp_src_ip  ON false_positives(src_ip);

-- ============================================================
-- 10. blocked_ips  (iptables firewall actions by the agent)
-- ============================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    reason      TEXT,
    blocked_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP,                     -- NULL = permanent
    active      INTEGER NOT NULL DEFAULT 1,    -- 0|1
    blocked_by  TEXT DEFAULT 'agent'            -- agent|manual
);

CREATE INDEX IF NOT EXISTS idx_blocked_ip     ON blocked_ips(ip);
CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(active);

-- ============================================================
-- 11. honeypot_events  (SSH:2222 / HTTP:8888 / MySQL:3307)
-- ============================================================
CREATE TABLE IF NOT EXISTS honeypot_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    service    TEXT NOT NULL,                  -- ssh|http|mysql
    src_ip     TEXT NOT NULL,
    src_port   INTEGER,
    username   TEXT,
    password   TEXT,
    payload    TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_honeypot_src     ON honeypot_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_service ON honeypot_events(service);

-- ============================================================
-- 12. email_notifications  (outbound SMTP log)
-- ============================================================
CREATE TABLE IF NOT EXISTS email_notifications (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    recipient    TEXT NOT NULL,
    subject      TEXT,
    alert_id     INTEGER,
    incident_id  INTEGER,
    status       TEXT,                          -- sent|failed
    error        TEXT,
    FOREIGN KEY (alert_id)    REFERENCES alerts(id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

-- ============================================================
-- 13. users  (API / mobile app users — Django auth_user lives separately)
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    email       TEXT,
    role        TEXT NOT NULL DEFAULT 'viewer',   -- admin|analyst|viewer
    api_token   TEXT UNIQUE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login  TIMESTAMP,
    active      INTEGER NOT NULL DEFAULT 1
);

-- ============================================================
-- 14. config  (runtime key/value store read by agent + dashboard)
-- ============================================================
CREATE TABLE IF NOT EXISTS config (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO config (key, value) VALUES
    ('schema_version',              '1'),
    ('correlation_window_seconds',  '300'),
    ('brute_force_threshold',       '5'),
    ('auto_block_enabled',          'true'),
    ('auto_block_severity_min',     '7'),
    ('block_duration_seconds',      '3600'),
    ('email_alerts_min_severity',   '6'),
    ('honeypot_ssh_port',           '2222'),
    ('honeypot_http_port',          '8888'),
    ('honeypot_mysql_port',         '3307'),
    ('fp_confidence_threshold',     '0.7'),
    ('dashboard_refresh_seconds',   '30');

-- ============================================================
-- VIEW 1 : recent alerts (last 24h) enriched with tactic/technique names
-- ============================================================
DROP VIEW IF EXISTS v_recent_alerts;
CREATE VIEW v_recent_alerts AS
SELECT
    a.id,
    a.timestamp,
    a.source,
    a.src_ip,
    a.src_port,
    a.dst_ip,
    a.dst_port,
    a.protocol,
    a.severity,
    a.level,
    a.mitre_tactic,
    a.mitre_technique,
    t.name  AS technique_name,
    ta.name AS tactic_name,
    a.description,
    a.status,
    a.fp_confidence,
    a.signature_id
FROM alerts a
LEFT JOIN mitre_techniques t  ON t.id  = a.mitre_technique
LEFT JOIN mitre_tactics    ta ON ta.id = a.mitre_tactic
WHERE a.timestamp >= datetime('now', '-24 hours')
ORDER BY a.timestamp DESC;

-- ============================================================
-- VIEW 2 : top attackers (last 7 days, by max severity then count)
-- ============================================================
DROP VIEW IF EXISTS v_top_attackers;
CREATE VIEW v_top_attackers AS
SELECT
    a.src_ip,
    COUNT(*)                          AS alert_count,
    MAX(a.severity)                   AS max_severity,
    MIN(a.timestamp)                  AS first_seen,
    MAX(a.timestamp)                  AS last_seen,
    COUNT(DISTINCT a.dst_ip)          AS target_count,
    COUNT(DISTINCT a.mitre_technique) AS techniques_used,
    (SELECT CASE WHEN EXISTS(SELECT 1 FROM blocked_ips b WHERE b.ip = a.src_ip AND b.active = 1) THEN 1 ELSE 0 END) AS blocked
FROM alerts a
WHERE a.src_ip IS NOT NULL
  AND a.status != 'false_positive'
  AND a.timestamp >= datetime('now', '-7 days')
GROUP BY a.src_ip
ORDER BY max_severity DESC, alert_count DESC;
