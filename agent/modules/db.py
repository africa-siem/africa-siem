"""
Module de connexion à la base de données SQLite SIEM Africa.

Caractéristiques :
- PRAGMA foreign_keys=ON systématique (par-session SQLite)
- PRAGMA journal_mode=WAL (concurrence lecture/écriture)
- Retry automatique sur SQLITE_BUSY
- Context manager pour gérer les transactions
- Thread-safe (check_same_thread=False)
- Logging des erreurs
"""

import sqlite3
import time
import logging
import threading
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger("siem-agent.db")

# Lock pour les opérations critiques
_db_lock = threading.RLock()


# ============================================================================
# CONFIGURATION
# ============================================================================

# Délai d'attente SQLite avant de retourner SQLITE_BUSY
SQLITE_TIMEOUT_SEC = 30

# Nombre de tentatives en cas de verrouillage
RETRY_MAX_ATTEMPTS = 5
RETRY_BASE_DELAY_SEC = 0.1  # exponential backoff


# ============================================================================
# OPENING / PRAGMA
# ============================================================================

def _apply_pragmas(conn):
    """Applique les PRAGMAs critiques sur une connexion SQLite."""
    pragmas = [
        "PRAGMA foreign_keys = ON",
        "PRAGMA journal_mode = WAL",
        "PRAGMA synchronous = NORMAL",
        "PRAGMA temp_store = MEMORY",
        "PRAGMA cache_size = -10000",  # 10 MB
        "PRAGMA busy_timeout = 30000",  # 30s
    ]
    for p in pragmas:
        try:
            conn.execute(p)
        except sqlite3.Error as e:
            log.warning(f"PRAGMA ignoré ({p}) : {e}")


def open_connection(db_path):
    """
    Ouvre une connexion SQLite avec tous les PRAGMA critiques.

    À utiliser pour les opérations one-shot. Pour des transactions multiples,
    préférer le context manager `transaction()`.
    """
    db_path = str(db_path)
    if not Path(db_path).exists():
        raise FileNotFoundError(f"BDD introuvable : {db_path}")

    conn = sqlite3.connect(
        db_path,
        timeout=SQLITE_TIMEOUT_SEC,
        check_same_thread=False,
        isolation_level=None  # autocommit OFF, on gère les transactions
    )
    conn.row_factory = sqlite3.Row
    _apply_pragmas(conn)
    return conn


# ============================================================================
# CONTEXT MANAGER : TRANSACTION
# ============================================================================

@contextmanager
def transaction(db_path):
    """
    Context manager pour gérer une transaction SQLite proprement.

    Usage :
        with transaction(db_path) as conn:
            conn.execute("INSERT INTO ...")
            conn.execute("UPDATE ...")
        # commit automatique à la sortie, rollback si exception
    """
    conn = None
    try:
        conn = open_connection(db_path)
        conn.execute("BEGIN")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


# ============================================================================
# RETRY HELPER (pour SQLITE_BUSY)
# ============================================================================

def execute_with_retry(db_path, sql, params=(), fetch_one=False, fetch_all=False):
    """
    Exécute une requête avec retry exponentiel en cas de SQLITE_BUSY.

    Args:
        db_path : chemin vers la BDD
        sql : requête SQL
        params : paramètres
        fetch_one : retourne le premier résultat (sqlite3.Row | None)
        fetch_all : retourne tous les résultats (List[sqlite3.Row])

    Returns:
        - lastrowid si INSERT (ni fetch_one ni fetch_all)
        - sqlite3.Row | None si fetch_one
        - List[sqlite3.Row] si fetch_all
    """
    last_err = None
    delay = RETRY_BASE_DELAY_SEC
    is_select = sql.strip().upper().startswith("SELECT")

    for attempt in range(RETRY_MAX_ATTEMPTS):
        try:
            with _db_lock:
                # Pour les écritures on ouvre en mode autocommit explicite
                conn = sqlite3.connect(
                    str(db_path),
                    timeout=SQLITE_TIMEOUT_SEC,
                    check_same_thread=False
                    # Note : isolation_level par défaut = None pas spécifié
                    # → mode "deferred" SQLite (autocommit avec BEGIN implicite)
                )
                conn.row_factory = sqlite3.Row
                _apply_pragmas(conn)
                try:
                    cur = conn.execute(sql, params)
                    if fetch_one:
                        result = cur.fetchone()
                    elif fetch_all:
                        result = cur.fetchall()
                    else:
                        # INSERT/UPDATE/DELETE — commit explicite
                        conn.commit()
                        result = cur.lastrowid
                    return result
                finally:
                    conn.close()
        except sqlite3.OperationalError as e:
            last_err = e
            if "locked" in str(e).lower() or "busy" in str(e).lower():
                log.warning(f"BDD verrouillée (tentative {attempt+1}/{RETRY_MAX_ATTEMPTS}) — retry dans {delay}s")
                time.sleep(delay)
                delay *= 2
                continue
            raise
        except sqlite3.Error as e:
            log.error(f"Erreur SQL : {e} | SQL: {sql[:100]}")
            raise

    log.error(f"Abandon après {RETRY_MAX_ATTEMPTS} tentatives : {last_err}")
    raise last_err


# ============================================================================
# HELPERS DOMAINE MÉTIER
# ============================================================================

def lookup_signature(db_path, rule_id, source=None):
    """
    Recherche une signature par rule_id (et optionnellement source).

    Args:
        rule_id : id de la signature (= rule_id natif Wazuh ou SID Snort)
        source : 'WAZUH' ou 'SNORT' (filtre optionnel)

    Returns:
        dict | None
    """
    if not rule_id:
        return None

    if source:
        sql = """
            SELECT s.*, sc.code AS category_code, sc.name AS category_name,
                   sc.color_hex,
                   mt.technique_id AS mitre_technique_id,
                   mt.name AS mitre_technique_name,
                   mt2.tactic_id AS mitre_tactic_id,
                   mt2.name AS mitre_tactic_name
            FROM signatures s
            LEFT JOIN signature_categories sc ON s.category_id = sc.id
            LEFT JOIN mitre_techniques mt ON s.technique_id = mt.id
            LEFT JOIN mitre_tactics mt2 ON mt.tactic_id = mt2.id
            WHERE s.id = ? AND s.source = ? AND s.is_active = 1
            LIMIT 1
        """
        params = (rule_id, source)
    else:
        sql = """
            SELECT s.*, sc.code AS category_code, sc.name AS category_name,
                   sc.color_hex,
                   mt.technique_id AS mitre_technique_id,
                   mt.name AS mitre_technique_name,
                   mt2.tactic_id AS mitre_tactic_id,
                   mt2.name AS mitre_tactic_name
            FROM signatures s
            LEFT JOIN signature_categories sc ON s.category_id = sc.id
            LEFT JOIN mitre_techniques mt ON s.technique_id = mt.id
            LEFT JOIN mitre_tactics mt2 ON mt.tactic_id = mt2.id
            WHERE s.id = ? AND s.is_active = 1
            LIMIT 1
        """
        params = (rule_id,)

    row = execute_with_retry(db_path, sql, params, fetch_one=True)
    return dict(row) if row else None


def insert_raw_event(db_path, event_data):
    """
    Insère un événement brut dans raw_events.

    event_data doit contenir au minimum :
        - event_uuid (TEXT, généré par l'appelant via uuid.uuid4())
        - source_system (TEXT)
        - event_timestamp (TEXT ISO 8601)
        - src_ip, dst_ip (TEXT)
        - message (TEXT)
        - source_rule_id (INT)
        - raw_payload (JSON string)

    Returns: id de l'événement inséré
    """
    sql = """
        INSERT INTO raw_events (
            event_uuid, source_system, source_rule_id,
            event_timestamp, received_at,
            src_ip, src_port, dst_ip, dst_port, protocol,
            message, raw_payload, asset_id, processed
        ) VALUES (
            ?, ?, ?,
            ?, CURRENT_TIMESTAMP,
            ?, ?, ?, ?, ?,
            ?, ?, ?, 0
        )
    """
    params = (
        event_data.get("event_uuid"),
        event_data.get("source_system"),
        event_data.get("source_rule_id"),
        event_data.get("event_timestamp"),
        event_data.get("src_ip"),
        event_data.get("src_port"),
        event_data.get("dst_ip"),
        event_data.get("dst_port"),
        event_data.get("protocol"),
        event_data.get("message"),
        event_data.get("raw_payload"),
        event_data.get("asset_id"),
    )
    return execute_with_retry(db_path, sql, params)


def insert_alert(db_path, alert_data):
    """
    Insère une alerte enrichie dans la table alerts.

    Returns: id de l'alerte
    """
    sql = """
        INSERT INTO alerts (
            alert_uuid, signature_id, severity, confidence,
            title, description, src_ip, dst_ip, asset_id,
            event_count, first_seen, last_seen,
            status, enriched_data
        ) VALUES (
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?
        )
    """
    params = (
        alert_data.get("alert_uuid"),
        alert_data.get("signature_id"),
        alert_data.get("severity"),
        alert_data.get("confidence"),
        alert_data.get("title"),
        alert_data.get("description"),
        alert_data.get("src_ip"),
        alert_data.get("dst_ip"),
        alert_data.get("asset_id"),
        alert_data.get("event_count", 1),
        alert_data.get("first_seen"),
        alert_data.get("last_seen"),
        alert_data.get("status", "NEW"),
        alert_data.get("enriched_data"),
    )
    return execute_with_retry(db_path, sql, params)


def update_alert_status(db_path, alert_id, status, resolution_notes=None):
    """Met à jour le statut d'une alerte (déclenche les triggers SQL)."""
    sql = """
        UPDATE alerts
        SET status = ?,
            resolution_notes = COALESCE(?, resolution_notes),
            resolved_at = CASE WHEN ? IN ('RESOLVED','FALSE_POSITIVE','IGNORED')
                               THEN CURRENT_TIMESTAMP ELSE resolved_at END
        WHERE id = ?
    """
    return execute_with_retry(db_path, sql, (status, resolution_notes, status, alert_id))


def find_or_create_asset(db_path, ip_address, hostname=None):
    """
    Trouve un asset par IP ou en crée un automatiquement (asset auto-discover).

    Returns: dict de l'asset
    """
    if not ip_address:
        return None

    # Recherche
    row = execute_with_retry(
        db_path,
        "SELECT * FROM assets WHERE ip_address = ? AND deleted_at IS NULL LIMIT 1",
        (ip_address,),
        fetch_one=True
    )
    if row:
        return dict(row)

    # Création auto
    import uuid
    asset_uuid = str(uuid.uuid4())
    hostname = hostname or f"unknown-{ip_address}"

    asset_id = execute_with_retry(
        db_path,
        """
        INSERT INTO assets (
            asset_uuid, hostname, ip_address, asset_type,
            criticality, environment, is_active
        ) VALUES (?, ?, ?, 'OTHER', 'MEDIUM', 'PRODUCTION', 1)
        """,
        (asset_uuid, hostname, ip_address)
    )

    return {
        "id": asset_id,
        "asset_uuid": asset_uuid,
        "hostname": hostname,
        "ip_address": ip_address,
        "auto_created": True
    }


def get_setting(db_path, key, default=None):
    """Récupère un setting depuis la BDD."""
    row = execute_with_retry(
        db_path,
        "SELECT value FROM settings WHERE key = ? AND deleted_at IS NULL LIMIT 1",
        (key,),
        fetch_one=True
    )
    return row["value"] if row else default


# ============================================================================
# HEALTHCHECK
# ============================================================================

def healthcheck(db_path):
    """
    Vérifie que la BDD est accessible et saine.

    Returns: dict avec les indicateurs de santé
    """
    result = {
        "db_path": str(db_path),
        "exists": False,
        "readable": False,
        "writable": False,
        "tables_ok": False,
        "fk_ok": False,
        "integrity_ok": False,
    }

    if not Path(db_path).exists():
        return result
    result["exists"] = True

    try:
        conn = open_connection(db_path)

        # Lecture
        cur = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        nb_tables = cur.fetchone()[0]
        result["readable"] = True
        result["tables_ok"] = nb_tables >= 22

        # FK check (vraie intégrité)
        cur = conn.execute("PRAGMA foreign_key_check")
        violations = cur.fetchall()
        result["fk_ok"] = len(violations) == 0

        # Integrity check
        cur = conn.execute("PRAGMA integrity_check")
        result["integrity_ok"] = cur.fetchone()[0] == "ok"

        # Test écriture (sur une table de test inoffensive)
        try:
            conn.execute("BEGIN")
            conn.execute("UPDATE settings SET updated_at = updated_at WHERE id = 1")
            conn.execute("ROLLBACK")
            result["writable"] = True
        except sqlite3.Error:
            result["writable"] = False

        conn.close()
    except Exception as e:
        log.error(f"Healthcheck failed : {e}")

    return result
