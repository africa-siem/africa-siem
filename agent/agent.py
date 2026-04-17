#!/usr/bin/env python3
"""
SIEM Africa - Module 3: intelligent agent.

Responsibilities
----------------
1. Tail /var/ossec/logs/alerts/alerts.json (we DO NOT use the Wazuh /alerts API).
2. Enrich each alert with a MITRE technique + signature lookup from SQLite.
3. Score false-positive confidence using signature baseline + historical feedback.
4. Correlate alerts by src_ip within a sliding window to build attack chains.
5. Send SMTP email for high-severity alerts / new correlations.
6. Block attacking IPs with iptables when auto-block is enabled.
7. Run honeypots on SSH:2222, HTTP:8888, MySQL:3307 and log hits to the DB.

Project rules honored here:
- sqlite3.Row has no .get() — we always wrap with dict(row) before .get().
- No PRAGMA journal_mode = WAL.
- PID file is under /var/log/siem-africa, not /var/run.
- Reads alerts.json directly (no Wazuh API).
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import queue
import signal
import smtplib
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ============================================================
# Paths & constants
# ============================================================
INSTALL_DIR = Path("/opt/siem-africa")
DB_PATH = INSTALL_DIR / "siem_africa.db"
ENV_PATH = INSTALL_DIR / ".env"
SMTP_CONF = INSTALL_DIR / "smtp.conf"

WAZUH_ALERTS = Path("/var/ossec/logs/alerts/alerts.json")
SNORT_FAST = Path("/var/log/snort/alert")

LOG_DIR = Path("/var/log/siem-africa")
PID_FILE = LOG_DIR / "agent.pid"
AGENT_LOG = LOG_DIR / "agent.log"

IPTABLES_CHAIN = "SIEM-AFRICA"

# ============================================================
# Logging
# ============================================================
log = logging.getLogger("siem-africa")


def setup_logging(level: str = "INFO") -> None:
    log.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s [%(threadName)s] %(message)s"
    )
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            str(AGENT_LOG), maxBytes=10 * 1024 * 1024, backupCount=5
        )
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except PermissionError:
        log.warning("cannot write to %s (permissions) — logging to stderr only", AGENT_LOG)


# ============================================================
# .env loader (flat KEY=VALUE file from Module 1)
# ============================================================
def load_env(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception as exc:
        log.warning("cannot read %s: %s", path, exc)
    return env


# ============================================================
# DB helpers
# ============================================================
def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def row_to_dict(row: Optional[sqlite3.Row]) -> Dict[str, Any]:
    """sqlite3.Row does not support .get() — always convert first."""
    return dict(row) if row is not None else {}


def db_config(conn: sqlite3.Connection, key: str, default: Optional[str] = None) -> Optional[str]:
    cur = conn.execute("SELECT value FROM config WHERE key = ?", (key,))
    d = row_to_dict(cur.fetchone())
    return d.get("value", default) if d else default


def db_config_int(conn: sqlite3.Connection, key: str, default: int) -> int:
    v = db_config(conn, key)
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def db_config_bool(conn: sqlite3.Connection, key: str, default: bool) -> bool:
    v = db_config(conn, key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y", "oui")


# ============================================================
# Signatures / MITRE lookups (cached in memory)
# ============================================================
class SignatureIndex:
    """In-memory index of active signatures for fast keyword matching."""

    def __init__(self) -> None:
        self.signatures: List[Dict[str, Any]] = []
        self.by_id: Dict[str, Dict[str, Any]] = {}
        self.loaded_at: float = 0.0

    def reload(self) -> None:
        conn = db_conn()
        try:
            cur = conn.execute(
                """
                SELECT s.id, s.technique_id, s.name, s.description, s.severity,
                       s.keywords, s.fp_likelihood,
                       t.tactic_id AS tactic_id,
                       t.name      AS technique_name
                FROM signatures s
                LEFT JOIN mitre_techniques t ON t.id = s.technique_id
                WHERE s.active = 1
                """
            )
            sigs: List[Dict[str, Any]] = []
            for raw in cur.fetchall():
                d = row_to_dict(raw)
                kw = (d.get("keywords") or "").lower()
                d["_kw_list"] = [k.strip() for k in kw.split("|") if k.strip()]
                sigs.append(d)
            self.signatures = sigs
            self.by_id = {s["id"]: s for s in sigs}
            self.loaded_at = time.time()
            log.info("signatures loaded: %d", len(sigs))
        finally:
            conn.close()

    def match(self, text: str) -> List[Dict[str, Any]]:
        if not text:
            return []
        low = text.lower()
        hits: List[Dict[str, Any]] = []
        for s in self.signatures:
            for kw in s["_kw_list"]:
                if kw and kw in low:
                    hits.append(s)
                    break
        return hits


# ============================================================
# False-positive confidence scorer
# ============================================================
def fp_confidence(
    conn: sqlite3.Connection,
    base_fp_likelihood: float,
    src_ip: Optional[str],
    rule_id: Optional[str],
    signature_id: Optional[str],
) -> float:
    """Return a 0..1 probability that the alert is a false positive.

    Combines the signature's baseline fp_likelihood with historical feedback:
    - Past FP markings for the same src_ip / rule_id push the score up.
    - Past confirmed incidents for the same src_ip push the score down.
    - Fresh keys with no history fall back to the baseline.
    """
    base = max(0.0, min(1.0, float(base_fp_likelihood or 0.3)))
    if not src_ip and not rule_id and not signature_id:
        return base

    fp_count = 0
    confirmed_count = 0
    if src_ip:
        cur = conn.execute(
            "SELECT COUNT(*) FROM false_positives WHERE src_ip = ?", (src_ip,)
        )
        fp_count += int(cur.fetchone()[0] or 0)
        cur = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE src_ip = ? AND status = 'confirmed'",
            (src_ip,),
        )
        confirmed_count += int(cur.fetchone()[0] or 0)
    if rule_id:
        cur = conn.execute(
            "SELECT COUNT(*) FROM false_positives WHERE rule_id = ?", (rule_id,)
        )
        fp_count += int(cur.fetchone()[0] or 0)
    if signature_id:
        cur = conn.execute(
            "SELECT COUNT(*) FROM false_positives WHERE signature_id = ?",
            (signature_id,),
        )
        fp_count += int(cur.fetchone()[0] or 0)

    total = fp_count + confirmed_count
    if total < 3:
        return base

    ratio = fp_count / float(total)
    weight_history = min(0.7, total / 20.0)
    return max(0.0, min(1.0, base * (1.0 - weight_history) + ratio * weight_history))


# ============================================================
# iptables blocker
# ============================================================
class IptablesBlocker:
    """Manages a dedicated iptables chain used to drop attacker IPs.

    We never flush system iptables or touch other chains.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ensure_chain()

    def _run(self, args: Iterable[str]) -> Tuple[int, str]:
        try:
            p = subprocess.run(
                ["iptables", *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return p.returncode, (p.stderr or p.stdout).strip()
        except FileNotFoundError:
            return 127, "iptables not installed"
        except Exception as exc:
            return 1, str(exc)

    def _ensure_chain(self) -> None:
        with self._lock:
            rc, _ = self._run(["-nL", IPTABLES_CHAIN])
            if rc != 0:
                self._run(["-N", IPTABLES_CHAIN])
            # Make sure INPUT references our chain (idempotent)
            rc, _ = self._run(["-C", "INPUT", "-j", IPTABLES_CHAIN])
            if rc != 0:
                self._run(["-I", "INPUT", "1", "-j", IPTABLES_CHAIN])

    def block(self, ip: str, reason: str, duration_seconds: Optional[int]) -> bool:
        if not ip or ip in ("127.0.0.1", "0.0.0.0", "::1"):
            return False
        with self._lock:
            rc, _ = self._run(["-C", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])
            if rc != 0:
                rc2, err = self._run(["-A", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])
                if rc2 != 0:
                    log.warning("iptables block failed for %s: %s", ip, err)
                    return False
        conn = db_conn()
        try:
            expires = None
            if duration_seconds and duration_seconds > 0:
                expires = (datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)).isoformat()
            conn.execute(
                "INSERT INTO blocked_ips (ip, reason, expires_at, active, blocked_by) "
                "VALUES (?, ?, ?, 1, 'agent')",
                (ip, reason, expires),
            )
        finally:
            conn.close()
        log.warning("BLOCKED %s (%s)", ip, reason)
        return True

    def unblock_expired(self) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = db_conn()
        count = 0
        try:
            cur = conn.execute(
                "SELECT id, ip FROM blocked_ips "
                "WHERE active = 1 AND expires_at IS NOT NULL AND expires_at < ?",
                (now_iso,),
            )
            rows = [row_to_dict(r) for r in cur.fetchall()]
            for r in rows:
                ip = r.get("ip")
                if not ip:
                    continue
                with self._lock:
                    self._run(["-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])
                conn.execute("UPDATE blocked_ips SET active = 0 WHERE id = ?", (r["id"],))
                count += 1
                log.info("unblocked %s (expired)", ip)
        finally:
            conn.close()
        return count


# ============================================================
# SMTP notifier
# ============================================================
class EmailNotifier:
    def __init__(self, env: Dict[str, str]) -> None:
        self.alert_email = env.get("ALERT_EMAIL", "")
        self.org_name = env.get("ORG_NAME", "SIEM Africa")
        # SMTP settings live in /opt/siem-africa/smtp.conf (written by install-smtp.sh)
        self.smtp_host = "localhost"
        self.smtp_port = 25
        self.smtp_user: Optional[str] = None
        self.smtp_pass: Optional[str] = None
        self.smtp_tls = False
        self.smtp_from = f"SIEM Africa <noreply@{socket.gethostname()}>"
        self._load_smtp_conf()

    def _load_smtp_conf(self) -> None:
        if not SMTP_CONF.exists():
            return
        cfg = load_env(SMTP_CONF)
        self.smtp_host = cfg.get("SMTP_HOST", self.smtp_host)
        try:
            self.smtp_port = int(cfg.get("SMTP_PORT", str(self.smtp_port)))
        except ValueError:
            pass
        self.smtp_user = cfg.get("SMTP_USER") or None
        self.smtp_pass = cfg.get("SMTP_PASS") or None
        self.smtp_tls = cfg.get("SMTP_TLS", "false").lower() in ("1", "true", "yes", "on")
        self.smtp_from = cfg.get("SMTP_FROM", self.smtp_from)

    def enabled(self) -> bool:
        return bool(self.alert_email)

    def send(self, subject: str, body: str, alert_id: Optional[int] = None) -> bool:
        if not self.enabled():
            return False
        msg = MIMEMultipart()
        msg["From"] = self.smtp_from
        msg["To"] = self.alert_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        status = "failed"
        error: Optional[str] = None
        try:
            if self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=15)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15)
                if self.smtp_tls:
                    server.starttls()
            if self.smtp_user and self.smtp_pass:
                server.login(self.smtp_user, self.smtp_pass)
            server.sendmail(self.smtp_from, [self.alert_email], msg.as_string())
            server.quit()
            status = "sent"
            log.info("email sent to %s: %s", self.alert_email, subject)
        except Exception as exc:
            error = str(exc)
            log.warning("email failed: %s", error)
        finally:
            conn = db_conn()
            try:
                conn.execute(
                    "INSERT INTO email_notifications (recipient, subject, alert_id, status, error) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (self.alert_email, subject, alert_id, status, error),
                )
            finally:
                conn.close()
        return status == "sent"


# ============================================================
# Wazuh alerts.json reader
# ============================================================
class AlertReader(threading.Thread):
    def __init__(self, path: Path, out_queue: "queue.Queue[Dict[str, Any]]", stop: threading.Event) -> None:
        super().__init__(daemon=True, name="alert-reader")
        self.path = path
        self.queue = out_queue
        self.stop = stop
        self._fp = None
        self._inode: Optional[int] = None

    def _open(self) -> None:
        try:
            self._fp = open(self.path, "r", encoding="utf-8", errors="replace")
            # tail: start at end of file so we only see NEW alerts
            self._fp.seek(0, os.SEEK_END)
            self._inode = os.fstat(self._fp.fileno()).st_ino
            log.info("tailing %s (inode=%s)", self.path, self._inode)
        except FileNotFoundError:
            self._fp = None

    def run(self) -> None:
        while not self.stop.is_set():
            if self._fp is None:
                self._open()
                if self._fp is None:
                    time.sleep(3)
                    continue
            line = self._fp.readline()
            if not line:
                # Detect rotation / truncation
                try:
                    st = os.stat(self.path)
                    if st.st_ino != self._inode or st.st_size < self._fp.tell():
                        log.info("%s rotated — reopening", self.path)
                        self._fp.close()
                        self._fp = None
                        continue
                except FileNotFoundError:
                    if self._fp:
                        self._fp.close()
                    self._fp = None
                    time.sleep(3)
                    continue
                time.sleep(0.5)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            try:
                self.queue.put(evt, timeout=1)
            except queue.Full:
                log.warning("alert queue full — dropping one")


# ============================================================
# Alert processor
# ============================================================
def parse_wazuh_alert(evt: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Wazuh alerts.json entry into the shape stored in the `alerts` table."""
    rule = evt.get("rule") or {}
    data = evt.get("data") or {}
    agent = evt.get("agent") or {}

    ts = evt.get("timestamp") or ""
    # Wazuh timestamp: "2024-01-01T12:34:56.789+0000" -> keep as-is (ISO-compatible enough)
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc).isoformat()

    full_log = evt.get("full_log") or data.get("full_log") or ""
    description = rule.get("description") or ""
    message = f"{description} | {full_log}".strip(" |")

    level = int(rule.get("level") or 0)
    # Normalize Wazuh level (0..15) -> severity (1..10)
    severity = max(1, min(10, int(round(level * (10.0 / 15.0))))) if level else 1

    # Optional embedded MITRE mapping in Wazuh rule
    mitre = rule.get("mitre") or {}
    mt_tactic = None
    mt_technique = None
    if isinstance(mitre, dict):
        tacs = mitre.get("tactic") or []
        tecs = mitre.get("technique") or mitre.get("id") or []
        if isinstance(tacs, list) and tacs:
            mt_tactic = str(tacs[0])
        if isinstance(tecs, list) and tecs:
            mt_technique = str(tecs[0])

    src_port = data.get("srcport") or data.get("src_port")
    dst_port = data.get("dstport") or data.get("dst_port")

    def _as_int(v: Any) -> Optional[int]:
        try:
            return int(v) if v not in (None, "", "any") else None
        except (TypeError, ValueError):
            return None

    return {
        "uid": evt.get("id") or f"{ts}-{rule.get('id', '?')}",
        "timestamp": ts,
        "source": "wazuh",
        "rule_id": str(rule.get("id") or ""),
        "agent_id": str(agent.get("id") or ""),
        "level": level,
        "severity": severity,
        "src_ip": (data.get("srcip") or data.get("src_ip") or "") or None,
        "src_port": _as_int(src_port),
        "dst_ip": (data.get("dstip") or data.get("dst_ip") or "") or None,
        "dst_port": _as_int(dst_port),
        "protocol": data.get("protocol") or None,
        "description": description,
        "raw_message": message[:4000],
        "mitre_tactic": mt_tactic,
        "mitre_technique": mt_technique,
    }


def ingest_alert(
    conn: sqlite3.Connection,
    sig_index: SignatureIndex,
    alert: Dict[str, Any],
) -> Optional[int]:
    """Store + enrich a single alert. Returns its DB id (or None on dedup)."""
    # Deduplicate by uid
    cur = conn.execute("SELECT id FROM alerts WHERE uid = ?", (alert.get("uid"),))
    existing = cur.fetchone()
    if existing:
        return None

    # Signature matching
    hits = sig_index.match(alert.get("raw_message") or "")
    sig: Dict[str, Any] = hits[0] if hits else {}
    if sig:
        alert["signature_id"] = sig.get("id")
        if not alert.get("mitre_technique") and sig.get("technique_id"):
            alert["mitre_technique"] = sig["technique_id"]
        if not alert.get("mitre_tactic") and sig.get("tactic_id"):
            alert["mitre_tactic"] = sig["tactic_id"]
        # Bias severity by signature
        alert["severity"] = max(int(alert.get("severity") or 0), int(sig.get("severity") or 0))

    # FP scoring
    fp = fp_confidence(
        conn,
        float(sig.get("fp_likelihood", 0.3)),
        alert.get("src_ip"),
        alert.get("rule_id"),
        alert.get("signature_id"),
    )
    alert["fp_confidence"] = round(fp, 3)

    cur = conn.execute(
        """
        INSERT INTO alerts
            (uid, timestamp, source, rule_id, signature_id, agent_id, level, severity,
             src_ip, src_port, dst_ip, dst_port, protocol, description, raw_message,
             mitre_tactic, mitre_technique, fp_confidence, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
        """,
        (
            alert.get("uid"),
            alert.get("timestamp"),
            alert.get("source"),
            alert.get("rule_id"),
            alert.get("signature_id"),
            alert.get("agent_id"),
            alert.get("level"),
            alert.get("severity"),
            alert.get("src_ip"),
            alert.get("src_port"),
            alert.get("dst_ip"),
            alert.get("dst_port"),
            alert.get("protocol"),
            alert.get("description"),
            alert.get("raw_message"),
            alert.get("mitre_tactic"),
            alert.get("mitre_technique"),
            alert.get("fp_confidence"),
        ),
    )
    return int(cur.lastrowid or 0)


# ============================================================
# Correlation
# ============================================================
def correlate_recent(conn: sqlite3.Connection, window_seconds: int) -> int:
    """Group alerts by src_ip inside the recent window into a correlation row.

    Returns the number of correlations touched (created or refreshed).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    cur = conn.execute(
        """
        SELECT src_ip,
               COUNT(*)                               AS cnt,
               MIN(timestamp)                         AS first_seen,
               MAX(timestamp)                         AS last_seen,
               MAX(severity)                          AS max_sev,
               GROUP_CONCAT(DISTINCT mitre_tactic)    AS tactics,
               GROUP_CONCAT(DISTINCT mitre_technique) AS techniques
        FROM alerts
        WHERE src_ip IS NOT NULL
          AND timestamp >= ?
          AND status != 'false_positive'
        GROUP BY src_ip
        HAVING cnt >= 2
        """,
        (cutoff,),
    )
    touched = 0
    for raw in cur.fetchall():
        d = row_to_dict(raw)
        src = d.get("src_ip")
        if not src:
            continue
        name = f"Activity from {src}"
        exist = conn.execute(
            "SELECT id FROM correlations WHERE src_ip = ? AND status = 'open'",
            (src,),
        ).fetchone()
        if exist:
            cid = row_to_dict(exist).get("id")
            conn.execute(
                """
                UPDATE correlations
                SET alert_count = ?, max_severity = ?, last_seen = ?,
                    tactics = ?, techniques = ?
                WHERE id = ?
                """,
                (d.get("cnt"), d.get("max_sev"), d.get("last_seen"),
                 d.get("tactics"), d.get("techniques"), cid),
            )
        else:
            conn.execute(
                """
                INSERT INTO correlations
                    (name, description, src_ip, first_seen, last_seen,
                     alert_count, max_severity, tactics, techniques, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                """,
                (name, f"Correlated alerts from {src}", src,
                 d.get("first_seen"), d.get("last_seen"),
                 d.get("cnt"), d.get("max_sev"),
                 d.get("tactics"), d.get("techniques")),
            )
        touched += 1
    return touched


# ============================================================
# Honeypots
# ============================================================
def record_honeypot(service: str, src_ip: str, src_port: Optional[int],
                    username: Optional[str], password: Optional[str],
                    payload: Optional[str], user_agent: Optional[str] = None) -> None:
    try:
        conn = db_conn()
        try:
            conn.execute(
                "INSERT INTO honeypot_events (service, src_ip, src_port, username, password, payload, user_agent) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (service, src_ip, src_port, username, password,
                 (payload or "")[:4000], user_agent),
            )
        finally:
            conn.close()
    except Exception as exc:
        log.warning("honeypot record failed (%s): %s", service, exc)


class _SSHHoneypotHandler(socketserver.BaseRequestHandler):
    """Minimal SSH honeypot: send fake banner, log whatever the client sends."""

    def handle(self) -> None:
        src_ip, src_port = self.client_address[:2]
        try:
            self.request.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11\r\n")
            self.request.settimeout(5)
            data = b""
            try:
                while len(data) < 2048:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, OSError):
                pass
            payload = data.decode("latin-1", errors="replace")
        except Exception as exc:
            log.debug("ssh hp error: %s", exc)
            payload = "<error>"
        log.warning("honeypot SSH hit from %s:%s (%d bytes)", src_ip, src_port, len(payload))
        record_honeypot("ssh", src_ip, src_port, None, None, payload)


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _MySQLHoneypotHandler(socketserver.BaseRequestHandler):
    """Minimal MySQL honeypot: send handshake packet, capture client auth."""

    def handle(self) -> None:
        src_ip, src_port = self.client_address[:2]
        try:
            # Build a fake MySQL handshake v10 (protocol 10, server 5.7.42 fake)
            version = b"5.7.42-siem-africa\x00"
            thread_id = struct.pack("<I", 1234)
            salt1 = b"12345678"
            capabilities = struct.pack("<H", 0xFFFF)
            charset = b"\x21"                       # utf8 general
            status = struct.pack("<H", 2)
            caps_upper = struct.pack("<H", 0x81FF)
            auth_len = b"\x15"
            reserved = b"\x00" * 10
            salt2 = b"123456789012\x00"
            auth_plugin = b"mysql_native_password\x00"
            payload = (
                b"\x0a" + version + thread_id + salt1 + b"\x00" +
                capabilities + charset + status + caps_upper +
                auth_len + reserved + salt2 + auth_plugin
            )
            header = struct.pack("<I", len(payload))[:3] + b"\x00"
            self.request.sendall(header + payload)
            self.request.settimeout(5)
            buf = b""
            try:
                while len(buf) < 4096:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
            except (socket.timeout, OSError):
                pass
            username = ""
            if len(buf) > 36:
                try:
                    remainder = buf[36:]
                    end = remainder.find(b"\x00")
                    if end != -1:
                        username = remainder[:end].decode("latin-1", errors="replace")
                except Exception:
                    pass
        except Exception as exc:
            log.debug("mysql hp error: %s", exc)
            buf = b""
            username = ""
        log.warning("honeypot MySQL hit from %s:%s (user=%r)", src_ip, src_port, username)
        record_honeypot("mysql", src_ip, src_port, username or None, None,
                        buf.hex()[:2000])


class _HTTPHoneypotHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.52 (Ubuntu)"

    def _log_hit(self, method: str) -> None:
        src_ip, src_port = self.client_address[:2]
        ua = self.headers.get("User-Agent", "")
        body = ""
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if 0 < length <= 16 * 1024:
                body = self.rfile.read(length).decode("latin-1", errors="replace")
        except Exception:
            pass
        payload = f"{method} {self.path} HTTP/1.1\n{self.headers}\n\n{body}"
        log.warning("honeypot HTTP %s %s from %s:%s (ua=%r)", method, self.path, src_ip, src_port, ua)
        record_honeypot("http", src_ip, src_port, None, None, payload, user_agent=ua)

    def _respond(self) -> None:
        html = (
            b"<html><head><title>Admin Login</title></head>"
            b"<body><h1>It works!</h1><form method='post' action='/login'>"
            b"<input name='user'/><input type='password' name='pass'/>"
            b"<button type='submit'>Login</button></form></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def do_GET(self) -> None:  # noqa: N802
        self._log_hit("GET")
        self._respond()

    def do_POST(self) -> None:  # noqa: N802
        self._log_hit("POST")
        self._respond()

    def log_message(self, fmt: str, *args: Any) -> None:  # silence stdlib logging
        return


def run_ssh_honeypot(port: int, stop: threading.Event) -> None:
    try:
        srv = _ThreadingTCPServer(("0.0.0.0", port), _SSHHoneypotHandler)
    except OSError as exc:
        log.error("cannot bind SSH honeypot on %s: %s", port, exc)
        return
    log.info("honeypot SSH listening on 0.0.0.0:%s", port)
    t = threading.Thread(target=srv.serve_forever, daemon=True, name="hp-ssh")
    t.start()
    stop.wait()
    srv.shutdown()
    srv.server_close()


def run_http_honeypot(port: int, stop: threading.Event) -> None:
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", port), _HTTPHoneypotHandler)
    except OSError as exc:
        log.error("cannot bind HTTP honeypot on %s: %s", port, exc)
        return
    log.info("honeypot HTTP listening on 0.0.0.0:%s", port)
    t = threading.Thread(target=srv.serve_forever, daemon=True, name="hp-http")
    t.start()
    stop.wait()
    srv.shutdown()
    srv.server_close()


def run_mysql_honeypot(port: int, stop: threading.Event) -> None:
    try:
        srv = _ThreadingTCPServer(("0.0.0.0", port), _MySQLHoneypotHandler)
    except OSError as exc:
        log.error("cannot bind MySQL honeypot on %s: %s", port, exc)
        return
    log.info("honeypot MySQL listening on 0.0.0.0:%s", port)
    t = threading.Thread(target=srv.serve_forever, daemon=True, name="hp-mysql")
    t.start()
    stop.wait()
    srv.shutdown()
    srv.server_close()


# ============================================================
# Honeypot → alert bridge
# ============================================================
def ingest_honeypot_events(conn: sqlite3.Connection, since: datetime) -> int:
    """Turn new honeypot_events into high-severity alerts so correlation/email kick in."""
    cur = conn.execute(
        "SELECT id, timestamp, service, src_ip, src_port, payload "
        "FROM honeypot_events WHERE timestamp > ? ORDER BY id ASC",
        (since.isoformat(),),
    )
    rows = [row_to_dict(r) for r in cur.fetchall()]
    for r in rows:
        service = (r.get("service") or "").lower()
        sig_id = {
            "ssh": "SIG-341",
            "http": "SIG-344",
            "mysql": "SIG-346",
        }.get(service, "SIG-341")
        uid = f"honeypot-{service}-{r.get('id')}"
        exist = conn.execute("SELECT 1 FROM alerts WHERE uid = ?", (uid,)).fetchone()
        if exist:
            continue
        conn.execute(
            """
            INSERT INTO alerts
                (uid, timestamp, source, rule_id, signature_id, agent_id, level, severity,
                 src_ip, src_port, dst_ip, dst_port, protocol, description, raw_message,
                 mitre_tactic, mitre_technique, fp_confidence, status)
            VALUES (?, ?, 'honeypot', NULL, ?, '000', 10, 8, ?, ?, NULL, NULL, 'tcp',
                    ?, ?, 'TA0001', 'T1110.001', 0.05, 'new')
            """,
            (
                uid, r.get("timestamp"), sig_id,
                r.get("src_ip"), r.get("src_port"),
                f"Honeypot {service.upper()} hit",
                (r.get("payload") or "")[:2000],
            ),
        )
    return len(rows)


# ============================================================
# Main loop orchestration
# ============================================================
class Agent:
    def __init__(self) -> None:
        self.env = load_env(ENV_PATH)
        self.sig_index = SignatureIndex()
        self.sig_index.reload()
        self.notifier = EmailNotifier(self.env)
        self.blocker = IptablesBlocker()
        self.queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=10000)
        self.stop = threading.Event()
        self._last_correlation = 0.0
        self._last_signature_reload = time.time()
        self._last_honeypot_sync = datetime.now(timezone.utc) - timedelta(minutes=1)
        self._last_unblock_check = 0.0
        self._recent_notified: Dict[str, float] = {}

    def write_pid(self) -> None:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
        except PermissionError:
            log.warning("cannot write PID file at %s", PID_FILE)

    def start_honeypots(self) -> List[threading.Thread]:
        conn = db_conn()
        try:
            ssh_port = db_config_int(conn, "honeypot_ssh_port", 2222)
            http_port = db_config_int(conn, "honeypot_http_port", 8888)
            mysql_port = db_config_int(conn, "honeypot_mysql_port", 3307)
        finally:
            conn.close()
        threads = []
        for target, port in (
            (run_ssh_honeypot, ssh_port),
            (run_http_honeypot, http_port),
            (run_mysql_honeypot, mysql_port),
        ):
            t = threading.Thread(target=target, args=(port, self.stop), daemon=True,
                                 name=f"hp-{target.__name__}-{port}")
            t.start()
            threads.append(t)
        return threads

    def maybe_notify(self, alert_id: int, alert: Dict[str, Any], conn: sqlite3.Connection) -> None:
        min_sev = db_config_int(conn, "email_alerts_min_severity", 6)
        fp_max = float(db_config(conn, "fp_confidence_threshold", "0.7") or 0.7)
        if int(alert.get("severity") or 0) < min_sev:
            return
        if float(alert.get("fp_confidence") or 0.0) >= fp_max:
            return
        key = f"{alert.get('src_ip')}|{alert.get('signature_id')}"
        now = time.time()
        if key in self._recent_notified and (now - self._recent_notified[key]) < 600:
            return
        self._recent_notified[key] = now
        body = (
            f"Alert #{alert_id}\n"
            f"Time       : {alert.get('timestamp')}\n"
            f"Source     : {alert.get('source')}\n"
            f"Severity   : {alert.get('severity')}\n"
            f"Src IP     : {alert.get('src_ip')}\n"
            f"Dst IP:Port: {alert.get('dst_ip')}:{alert.get('dst_port')}\n"
            f"Technique  : {alert.get('mitre_technique')}\n"
            f"Signature  : {alert.get('signature_id')}\n"
            f"FP score   : {alert.get('fp_confidence')}\n"
            f"Description: {alert.get('description')}\n\n"
            f"Raw:\n{alert.get('raw_message')}\n"
        )
        subject = f"[SIEM Africa] Severity {alert.get('severity')} — {alert.get('description') or 'alert'}"
        self.notifier.send(subject, body, alert_id=alert_id)
        conn.execute("UPDATE alerts SET notified = 1 WHERE id = ?", (alert_id,))

    def maybe_block(self, alert: Dict[str, Any], conn: sqlite3.Connection) -> None:
        if not db_config_bool(conn, "auto_block_enabled", True):
            return
        min_sev = db_config_int(conn, "auto_block_severity_min", 7)
        duration = db_config_int(conn, "block_duration_seconds", 3600)
        fp_max = float(db_config(conn, "fp_confidence_threshold", "0.7") or 0.7)
        ip = alert.get("src_ip")
        if not ip or int(alert.get("severity") or 0) < min_sev:
            return
        if float(alert.get("fp_confidence") or 0.0) >= fp_max:
            return
        if ip.startswith("127.") or ip in ("0.0.0.0", "::1"):
            return
        # Private network grace: only block private IPs if severity is very high
        if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                         "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
            if int(alert.get("severity") or 0) < 9:
                return
        already = conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ? AND active = 1", (ip,)
        ).fetchone()
        if already:
            return
        reason = f"auto-block sev {alert.get('severity')} ({alert.get('signature_id') or alert.get('rule_id') or 'n/a'})"
        if self.blocker.block(ip, reason, duration):
            conn.execute("UPDATE alerts SET status = 'blocked' WHERE id = ? OR src_ip = ?", (alert.get("_db_id"), ip))

    def housekeeping(self, conn: sqlite3.Connection) -> None:
        now = time.time()
        if (now - self._last_correlation) > 30:
            try:
                window = db_config_int(conn, "correlation_window_seconds", 300)
                correlate_recent(conn, window)
            except Exception as exc:
                log.warning("correlation error: %s", exc)
            self._last_correlation = now
        if (now - self._last_unblock_check) > 60:
            try:
                self.blocker.unblock_expired()
            except Exception as exc:
                log.warning("unblock error: %s", exc)
            self._last_unblock_check = now
        if (now - self._last_signature_reload) > 600:
            try:
                self.sig_index.reload()
            except Exception as exc:
                log.warning("signature reload error: %s", exc)
            self._last_signature_reload = now
        # Pull honeypot hits as alerts
        try:
            ingest_honeypot_events(conn, self._last_honeypot_sync)
            self._last_honeypot_sync = datetime.now(timezone.utc)
        except Exception as exc:
            log.warning("honeypot ingest error: %s", exc)

    def run(self) -> None:
        self.write_pid()
        reader = AlertReader(WAZUH_ALERTS, self.queue, self.stop)
        reader.start()
        self.start_honeypots()
        log.info("agent started (pid=%s)", os.getpid())

        conn = db_conn()
        try:
            while not self.stop.is_set():
                try:
                    evt = self.queue.get(timeout=1)
                except queue.Empty:
                    self.housekeeping(conn)
                    continue
                try:
                    alert = parse_wazuh_alert(evt)
                    alert_id = ingest_alert(conn, self.sig_index, alert)
                    if alert_id:
                        alert["_db_id"] = alert_id
                        self.maybe_notify(alert_id, alert, conn)
                        self.maybe_block(alert, conn)
                except Exception as exc:
                    log.exception("process error: %s", exc)
                self.housekeeping(conn)
        finally:
            conn.close()
            try:
                if PID_FILE.exists():
                    PID_FILE.unlink()
            except OSError:
                pass
            log.info("agent stopped")


# ============================================================
# Entry point / signal handling
# ============================================================
def install_signal_handlers(agent: Agent) -> None:
    def _stop(signum: int, _frame: Any) -> None:
        log.info("received signal %s — stopping", signum)
        agent.stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _stop)
        except (OSError, ValueError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SIEM Africa intelligent agent")
    parser.add_argument("--log-level", default="INFO",
                        choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    parser.add_argument("--check", action="store_true",
                        help="sanity check (DB + alerts.json + signatures) and exit")
    args = parser.parse_args(argv)
    setup_logging(args.log_level)

    if not DB_PATH.exists():
        log.error("database not found at %s — install Module 2 first", DB_PATH)
        return 2

    if args.check:
        conn = db_conn()
        try:
            nsig = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        finally:
            conn.close()
        log.info("DB OK — %d signatures", nsig)
        log.info("Wazuh alerts file: %s (exists=%s)", WAZUH_ALERTS, WAZUH_ALERTS.exists())
        return 0

    agent = Agent()
    install_signal_handlers(agent)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
