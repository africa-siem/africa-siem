"""
Couche d'accès direct à la BDD SIEM Africa (siem.db).

Django ne fait PAS de migrations sur cette BDD — c'est le Module 2 qui la
gère. On accède via raw queries.
"""
import sqlite3
import logging
from contextlib import contextmanager
from django.conf import settings

log = logging.getLogger("siem-dashboard.db")


@contextmanager
def get_conn():
    """Connexion read+write avec FK et WAL."""
    conn = sqlite3.connect(settings.SIEM_DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    finally:
        conn.close()


def fetchall(sql, params=()):
    with get_conn() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def fetchone(sql, params=()):
    with get_conn() as c:
        row = c.execute(sql, params).fetchone()
        return dict(row) if row else None


def execute(sql, params=()):
    with get_conn() as c:
        c.execute("BEGIN")
        try:
            cur = c.execute(sql, params)
            c.execute("COMMIT")
            return cur.lastrowid
        except Exception:
            c.execute("ROLLBACK")
            raise


# ============================================================================
# AUTH (utilise la table users du Module 2)
# ============================================================================

def get_user_by_email(email):
    sql = """
        SELECT u.*, r.code AS role_code, r.name AS role_name,
               r.permissions AS role_permissions
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.email = ?
          AND u.is_active = 1
          AND u.deleted_at IS NULL
        LIMIT 1
    """
    return fetchone(sql, (email,))


def get_user_by_id(user_id):
    sql = """
        SELECT u.*, r.code AS role_code, r.name AS role_name,
               r.permissions AS role_permissions
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.id = ? AND u.is_active = 1 AND u.deleted_at IS NULL
        LIMIT 1
    """
    return fetchone(sql, (user_id,))


def update_last_login(user_id):
    execute(
        "UPDATE users SET last_login_at = CURRENT_TIMESTAMP, "
        "failed_login_count = 0 WHERE id = ?",
        (user_id,)
    )


def increment_failed_login(user_id):
    execute(
        "UPDATE users SET failed_login_count = failed_login_count + 1 WHERE id = ?",
        (user_id,)
    )


def update_password(user_id, new_password_hash):
    execute(
        "UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, "
        "must_change_pwd = 0 WHERE id = ?",
        (new_password_hash, user_id)
    )


# ============================================================================
# ALERTES
# ============================================================================

def list_alerts(severity=None, status=None, limit=100, offset=0):
    where = []
    params = []

    if severity:
        where.append("a.severity = ?")
        params.append(severity)

    if status:
        if status == "ACTIVE":
            where.append("a.status IN ('NEW','ACKNOWLEDGED','INVESTIGATING')")
        else:
            where.append("a.status = ?")
            params.append(status)

    where_clause = ("WHERE " + " AND ".join(where)) if where else ""

    sql = f"""
        SELECT a.*,
               s.name AS sig_name, s.description_fr AS sig_desc,
               s.source AS sig_source,
               sc.code AS category_code, sc.name AS category_name,
               sc.color_hex AS category_color,
               mt.technique_id AS mitre_tech_id,
               mt.name AS mitre_tech_name
        FROM alerts a
        LEFT JOIN signatures s ON a.signature_id = s.id
        LEFT JOIN signature_categories sc ON s.category_id = sc.id
        LEFT JOIN mitre_techniques mt ON s.technique_id = mt.id
        {where_clause}
        ORDER BY a.created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])
    return fetchall(sql, params)


def count_alerts(severity=None, status=None):
    where = []
    params = []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if status:
        if status == "ACTIVE":
            where.append("status IN ('NEW','ACKNOWLEDGED','INVESTIGATING')")
        else:
            where.append("status = ?")
            params.append(status)
    where_clause = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"SELECT COUNT(*) AS nb FROM alerts {where_clause}"
    row = fetchone(sql, params)
    return row["nb"] if row else 0


def get_alert(alert_id):
    sql = """
        SELECT a.*,
               s.name AS sig_name, s.description_fr AS sig_desc,
               s.remediation_fr AS sig_remediation,
               s.source AS sig_source, s.severity AS sig_severity,
               sc.code AS category_code, sc.name AS category_name,
               sc.color_hex AS category_color,
               mt.technique_id AS mitre_tech_id,
               mt.name AS mitre_tech_name,
               mt.description AS mitre_tech_desc,
               mt2.tactic_id AS mitre_tac_id, mt2.name AS mitre_tac_name,
               u.email AS assigned_email
        FROM alerts a
        LEFT JOIN signatures s ON a.signature_id = s.id
        LEFT JOIN signature_categories sc ON s.category_id = sc.id
        LEFT JOIN mitre_techniques mt ON s.technique_id = mt.id
        LEFT JOIN mitre_tactics mt2 ON mt.tactic_id = mt2.id
        LEFT JOIN users u ON a.assigned_to = u.id
        WHERE a.id = ?
    """
    return fetchone(sql, (alert_id,))


def get_alert_ai_explanation(alert_id):
    sql = """
        SELECT * FROM ai_explanations
        WHERE alert_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    """
    return fetchone(sql, (alert_id,))


def update_alert_status(alert_id, status, user_id, notes=None):
    sql = """
        UPDATE alerts
        SET status = ?,
            resolution_notes = COALESCE(?, resolution_notes),
            assigned_to = COALESCE(assigned_to, ?),
            resolved_at = CASE
                WHEN ? IN ('RESOLVED','FALSE_POSITIVE','IGNORED')
                THEN CURRENT_TIMESTAMP ELSE resolved_at END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """
    return execute(sql, (status, notes, user_id, status, alert_id))


# ============================================================================
# DASHBOARD METRICS
# ============================================================================

def get_dashboard_metrics():
    """Métriques agrégées pour la home page."""
    metrics = {}

    # Alertes par sévérité (dernières 24h)
    rows = fetchall("""
        SELECT severity, COUNT(*) AS nb
        FROM alerts
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY severity
    """)
    metrics["by_severity_24h"] = {r["severity"]: r["nb"] for r in rows}

    # Total alertes actives
    metrics["active_alerts"] = count_alerts(status="ACTIVE")

    # IPs bloquées actives
    row = fetchone("SELECT COUNT(*) AS nb FROM blocked_ips WHERE is_active = 1")
    metrics["blocked_ips"] = row["nb"] if row else 0

    # Honeypot hits 24h
    row = fetchone("""
        SELECT COUNT(*) AS nb FROM honeypot_hits
        WHERE hit_at >= datetime('now', '-24 hours')
    """)
    metrics["honeypot_24h"] = row["nb"] if row else 0

    # Alertes non résolues critiques
    row = fetchone("""
        SELECT COUNT(*) AS nb FROM alerts
        WHERE severity = 'CRITICAL'
          AND status IN ('NEW','ACKNOWLEDGED','INVESTIGATING')
    """)
    metrics["critical_open"] = row["nb"] if row else 0

    # Top 5 IPs attaquantes (7j)
    metrics["top_attackers"] = fetchall("""
        SELECT src_ip, COUNT(*) AS nb,
               MAX(severity) AS max_severity,
               MAX(created_at) AS last_seen
        FROM alerts
        WHERE created_at >= datetime('now', '-7 days')
          AND src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY nb DESC
        LIMIT 5
    """)

    # Top 5 signatures déclenchées (24h)
    metrics["top_signatures"] = fetchall("""
        SELECT a.signature_id, COUNT(*) AS nb,
               s.name, s.severity
        FROM alerts a
        LEFT JOIN signatures s ON a.signature_id = s.id
        WHERE a.created_at >= datetime('now', '-24 hours')
        GROUP BY a.signature_id
        ORDER BY nb DESC
        LIMIT 5
    """)

    return metrics


# ============================================================================
# FILTRES FAUX POSITIFS
# ============================================================================

def list_filters(active_only=True):
    where = "WHERE 1=1"
    if active_only:
        where += " AND af.is_active = 1 AND (af.expires_at IS NULL OR af.expires_at > CURRENT_TIMESTAMP)"

    sql = f"""
        SELECT af.*,
               s.name AS sig_name,
               u.email AS created_by_email
        FROM alert_filters af
        LEFT JOIN signatures s ON af.signature_id = s.id
        LEFT JOIN users u ON af.created_by = u.id
        {where}
        ORDER BY af.created_at DESC
    """
    return fetchall(sql)


def create_filter(name, signature_id, src_ip, action, reason, user_id,
                  filter_type="MANUAL"):
    import uuid
    sql = """
        INSERT INTO alert_filters (
            filter_uuid, name, signature_id, src_ip, action,
            filter_type, reason, created_by, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    """
    return execute(sql, (
        str(uuid.uuid4()), name[:200], signature_id, src_ip,
        action, filter_type, reason, user_id
    ))


def delete_filter(filter_id):
    """Soft delete : on désactive."""
    sql = "UPDATE alert_filters SET is_active = 0 WHERE id = ?"
    return execute(sql, (filter_id,))


# ============================================================================
# IPs BLOQUEES
# ============================================================================

def list_blocked_ips(active_only=True, limit=100):
    where = "WHERE 1=1"
    if active_only:
        where += " AND b.is_active = 1"

    sql = f"""
        SELECT b.*, s.name AS sig_name,
               u.email AS blocked_by_user_email
        FROM blocked_ips b
        LEFT JOIN signatures s ON b.signature_id = s.id
        LEFT JOIN users u ON b.blocked_by_user = u.id
        {where}
        ORDER BY b.blocked_at DESC
        LIMIT ?
    """
    return fetchall(sql, (limit,))


def unblock_ip_db(ip_id, user_id, reason="Manuel via dashboard"):
    sql = """
        UPDATE blocked_ips
        SET is_active = 0,
            unblocked_at = CURRENT_TIMESTAMP,
            unblocked_by = ?,
            unblock_reason = ?
        WHERE id = ?
    """
    return execute(sql, (user_id, reason, ip_id))


# ============================================================================
# SIGNATURES (pour formulaire de filtre)
# ============================================================================

def search_signatures(query, limit=20):
    sql = """
        SELECT id, name, severity, source
        FROM signatures
        WHERE is_active = 1
          AND (CAST(id AS TEXT) LIKE ? OR name LIKE ? OR description_fr LIKE ?)
        ORDER BY id
        LIMIT ?
    """
    q = f"%{query}%"
    return fetchall(sql, (q, q, q, limit))


# ============================================================================
# AUDIT
# ============================================================================

def log_audit(user_id, user_email, action, action_category,
              target_table=None, target_id=None, details=None,
              ip_address=None):
    import uuid
    sql = """
        INSERT INTO audit_log (
            audit_uuid, user_id, user_email, ip_address,
            action, action_category, target_table, target_id, details,
            performed_at, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'SUCCESS')
    """
    try:
        execute(sql, (
            str(uuid.uuid4()), user_id, user_email, ip_address,
            action[:100], action_category[:50],
            target_table, target_id, (details or "")[:2000]
        ))
    except Exception as e:
        log.error(f"Audit échoué : {e}")


# ============================================================================
# NOTIFICATIONS DASHBOARD
# ============================================================================

def list_notifications(user_id, unread_only=False, limit=20):
    where = "WHERE user_id = ?"
    if unread_only:
        where += " AND is_read = 0"
    sql = f"""
        SELECT * FROM notifications
        {where}
        ORDER BY created_at DESC
        LIMIT ?
    """
    return fetchall(sql, (user_id, limit))


def mark_notification_read(notif_id, user_id):
    sql = """
        UPDATE notifications
        SET is_read = 1, read_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
    """
    return execute(sql, (notif_id, user_id))


def count_unread_notifications(user_id):
    row = fetchone(
        "SELECT COUNT(*) AS nb FROM notifications WHERE user_id = ? AND is_read = 0",
        (user_id,)
    )
    return row["nb"] if row else 0


# ============================================================================
# MITRE ATT&CK
# ============================================================================

def get_mitre_matrix():
    """
    Retourne la matrice MITRE complète avec hits par technique.
    Format pour affichage : {tactic_id: {tactic_name, techniques: [...]}}
    """
    rows = fetchall("""
        SELECT
            t.tactic_id, t.name AS tactic_name, t.description AS tactic_desc,
            t.display_order AS tactic_order,
            tech.id AS tech_pk,
            tech.technique_id, tech.name AS tech_name,
            tech.description AS tech_desc,
            (SELECT COUNT(*) FROM signatures s WHERE s.technique_id = tech.id AND s.is_active = 1) AS sig_count,
            (SELECT COUNT(*) FROM alerts a
                JOIN signatures s ON a.signature_id = s.id
                WHERE s.technique_id = tech.id
                  AND a.created_at >= datetime('now', '-30 days')) AS alert_count_30d
        FROM mitre_tactics t
        LEFT JOIN mitre_techniques tech ON tech.tactic_id = t.id
        ORDER BY t.display_order, tech.technique_id
    """)

    matrix = {}
    for r in rows:
        tac_id = r["tactic_id"]
        if tac_id not in matrix:
            matrix[tac_id] = {
                "id": tac_id,
                "name": r["tactic_name"],
                "description": r["tactic_desc"],
                "order": r["tactic_order"],
                "techniques": [],
            }
        if r["technique_id"]:
            matrix[tac_id]["techniques"].append({
                "id": r["technique_id"],
                "name": r["tech_name"],
                "description": r["tech_desc"],
                "sig_count": r["sig_count"] or 0,
                "alert_count_30d": r["alert_count_30d"] or 0,
            })

    return sorted(matrix.values(), key=lambda x: x["order"])


def get_technique_alerts(technique_id, limit=50):
    """Liste les alertes pour une technique MITRE donnée."""
    return fetchall("""
        SELECT a.*, s.name AS sig_name
        FROM alerts a
        JOIN signatures s ON a.signature_id = s.id
        JOIN mitre_techniques mt ON s.technique_id = mt.id
        WHERE mt.technique_id = ?
        ORDER BY a.created_at DESC
        LIMIT ?
    """, (technique_id, limit))


# ============================================================================
# HONEYPOT HITS
# ============================================================================

def list_honeypot_hits(limit=100):
    return fetchall("""
        SELECT * FROM honeypot_hits
        ORDER BY hit_at DESC
        LIMIT ?
    """, (limit,))


def get_honeypot_stats():
    rows = fetchall("""
        SELECT honeypot_type, COUNT(*) AS nb,
               COUNT(DISTINCT src_ip) AS unique_ips,
               MAX(hit_at) AS last_hit
        FROM honeypot_hits
        WHERE hit_at >= datetime('now', '-30 days')
        GROUP BY honeypot_type
    """)
    return {r["honeypot_type"]: r for r in rows}


# ============================================================================
# USERS / RBAC
# ============================================================================

def list_users():
    return fetchall("""
        SELECT u.*,
               TRIM(COALESCE(u.first_name, '') || ' ' || COALESCE(u.last_name, '')) AS full_name,
               r.code AS role_code, r.name AS role_name
        FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE u.deleted_at IS NULL
        ORDER BY u.created_at DESC
    """)


def list_roles():
    return fetchall("SELECT * FROM roles ORDER BY id")


def create_user(email, password_hash, role_id, full_name=None):
    """full_name est splitté en first_name + last_name (schéma M2)."""
    import uuid
    first_name = ""
    last_name = ""
    if full_name:
        parts = full_name.strip().split(maxsplit=1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ""
    return execute("""
        INSERT INTO users (
            user_uuid, email, password_hash, role_id, first_name, last_name,
            is_active, must_change_pwd
        ) VALUES (?, ?, ?, ?, ?, ?, 1, 1)
    """, (str(uuid.uuid4()), email, password_hash, role_id, first_name, last_name))


def update_user_active(user_id, is_active):
    return execute(
        "UPDATE users SET is_active = ? WHERE id = ?",
        (1 if is_active else 0, user_id)
    )


def soft_delete_user(user_id):
    return execute(
        "UPDATE users SET deleted_at = CURRENT_TIMESTAMP, is_active = 0 WHERE id = ?",
        (user_id,)
    )


# ============================================================================
# SETTINGS
# ============================================================================

def list_settings():
    """Tous les paramètres système, groupés par catégorie."""
    rows = fetchall("""
        SELECT * FROM settings
        WHERE deleted_at IS NULL
        ORDER BY category, key
    """)
    grouped = {}
    for r in rows:
        cat = r["category"] or "general"
        grouped.setdefault(cat, []).append(r)
    return grouped


def update_setting(key, value, user_id):
    return execute("""
        UPDATE settings
        SET value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE key = ? AND deleted_at IS NULL
    """, (value, user_id, key))


# ============================================================================
# CHARTS - Données pour Chart.js
# ============================================================================

def alerts_timeline(days=7):
    """Alertes par jour pour les N derniers jours."""
    return fetchall("""
        SELECT
            date(created_at) AS day,
            COUNT(*) AS total,
            SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low
        FROM alerts
        WHERE created_at >= date('now', ?)
        GROUP BY date(created_at)
        ORDER BY day
    """, (f"-{days} days",))


def alerts_by_hour_24h():
    """Alertes par heure pour les dernières 24h."""
    return fetchall("""
        SELECT
            strftime('%H', created_at) AS hour,
            COUNT(*) AS nb
        FROM alerts
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    """)


def category_distribution():
    """Répartition des alertes par catégorie de signature."""
    return fetchall("""
        SELECT
            sc.name AS category,
            sc.color_hex,
            COUNT(*) AS nb
        FROM alerts a
        JOIN signatures s ON a.signature_id = s.id
        JOIN signature_categories sc ON s.category_id = sc.id
        WHERE a.created_at >= datetime('now', '-7 days')
        GROUP BY sc.id
        ORDER BY nb DESC
    """)


# ============================================================================
# EXPORT CSV
# ============================================================================

def alerts_for_export(severity=None, status=None, days=30):
    """Récupère les alertes pour export CSV."""
    where = ["a.created_at >= datetime('now', ?)"]
    params = [f"-{days} days"]

    if severity:
        where.append("a.severity = ?")
        params.append(severity)
    if status:
        where.append("a.status = ?")
        params.append(status)

    sql = f"""
        SELECT
            a.id, a.alert_uuid, a.severity, a.status, a.confidence,
            a.title, a.src_ip, a.dst_ip, a.event_count,
            a.first_seen, a.last_seen, a.created_at, a.resolved_at,
            s.id AS signature_id, s.name AS sig_name, s.source AS sig_source,
            sc.name AS category,
            mt.technique_id AS mitre_tech, mt.name AS mitre_name
        FROM alerts a
        LEFT JOIN signatures s ON a.signature_id = s.id
        LEFT JOIN signature_categories sc ON s.category_id = sc.id
        LEFT JOIN mitre_techniques mt ON s.technique_id = mt.id
        WHERE {' AND '.join(where)}
        ORDER BY a.created_at DESC
    """
    return fetchall(sql, params)
