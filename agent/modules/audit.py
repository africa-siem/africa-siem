"""
Module Audit — insertion automatique dans audit_log.

Enregistre les actions de l'agent (système) dans le journal d'audit central.
L'agent est représenté par user_id=NULL (action système).

Actions tracées :
- ALERT_CREATED : nouvelle alerte
- ALERT_FILTERED : alerte filtrée par un filtre FP
- AUTO_BLOCK : blocage iptables auto
- AUTO_UNBLOCK : déblocage auto
- HONEYPOT_HIT : hit honeypot
- AUTO_FILTER_CREATED : filtre auto créé par bruit-killer
- AI_GENERATED : explication IA générée
"""

import json
import logging
import uuid
import time

from modules import db

log = logging.getLogger("siem-agent.audit")


class Auditor:
    """
    Enregistreur d'audit pour les actions de l'agent.
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")

    # ========================================================================
    # API DE LOG GÉNÉRIQUE
    # ========================================================================

    def log(self, action, action_category, target_table=None, target_id=None,
            target_description=None, old_value=None, new_value=None,
            details=None, status="SUCCESS", error_message=None,
            duration_ms=None):
        """
        Insère une entrée dans audit_log.

        Args:
            action : nom de l'action (ex: 'ALERT_CREATED')
            action_category : AUTH/CONFIG/ALERT/INCIDENT/USER/ASSET/BLOCK/AI/FILTER/OTHER
            target_table : table affectée
            target_id : id de l'entité
            target_description : description courte
            old_value : ancienne valeur (sera JSON-encodée)
            new_value : nouvelle valeur (sera JSON-encodée)
            details : texte libre
            status : SUCCESS / FAILURE / PARTIAL
            error_message : si échec
            duration_ms : durée d'exécution
        """
        try:
            db.execute_with_retry(
                self.db_path,
                """
                INSERT INTO audit_log (
                    audit_uuid, user_id, user_email, ip_address, user_agent,
                    action, action_category,
                    target_table, target_id, target_description,
                    old_value, new_value, details,
                    status, error_message, duration_ms,
                    performed_at
                ) VALUES (
                    ?, NULL, 'siem-agent@system', '127.0.0.1', 'SIEM-Agent/1.0',
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    CURRENT_TIMESTAMP
                )
                """,
                (
                    str(uuid.uuid4()),
                    action[:100],
                    action_category[:50],
                    target_table,
                    target_id,
                    (target_description or "")[:500],
                    json.dumps(old_value, ensure_ascii=False, default=str) if old_value else None,
                    json.dumps(new_value, ensure_ascii=False, default=str) if new_value else None,
                    (details or "")[:2000] if details else None,
                    status,
                    (error_message or "")[:1000] if error_message else None,
                    duration_ms,
                )
            )
        except Exception as e:
            # Ne pas faire crash l'agent si audit échoue
            log.error(f"Erreur audit_log : {e}")

    # ========================================================================
    # HELPERS POUR ÉVÉNEMENTS COURANTS
    # ========================================================================

    def log_alert_created(self, alert_id, signature, info):
        """Trace la création d'une alerte."""
        self.log(
            action="ALERT_CREATED",
            action_category="ALERT",
            target_table="alerts",
            target_id=alert_id,
            target_description=f"{signature.get('name', '')[:200]} from {info.get('src_ip')}",
            new_value={
                "signature_id": signature["id"],
                "severity": signature.get("severity"),
                "src_ip": info.get("src_ip"),
                "dst_ip": info.get("dst_ip"),
            }
        )

    def log_alert_filtered(self, info, signature, filter_decision):
        """Trace une alerte filtrée."""
        self.log(
            action="ALERT_FILTERED",
            action_category="FILTER",
            target_table="alert_filters",
            target_id=filter_decision.get("filter_id"),
            target_description=filter_decision.get("reason", "")[:300],
            new_value={
                "signature_id": signature["id"],
                "src_ip": info.get("src_ip"),
                "action": filter_decision.get("action"),
            }
        )

    def log_block_ip(self, ip, alert_id, reason, duration_sec):
        """Trace un blocage IP."""
        self.log(
            action="AUTO_BLOCK",
            action_category="BLOCK",
            target_table="blocked_ips",
            target_description=f"{ip} bloquée ({duration_sec}s)",
            new_value={
                "ip_address": ip,
                "alert_id": alert_id,
                "reason": reason,
                "duration_sec": duration_sec,
            }
        )

    def log_unblock_ip(self, ip, reason):
        """Trace un déblocage IP."""
        self.log(
            action="AUTO_UNBLOCK",
            action_category="BLOCK",
            target_table="blocked_ips",
            target_description=f"{ip} débloquée ({reason})",
            new_value={"ip_address": ip, "reason": reason}
        )

    def log_honeypot_hit(self, service, ip, port):
        """Trace un hit honeypot."""
        self.log(
            action="HONEYPOT_HIT",
            action_category="ALERT",
            target_table="honeypot_hits",
            target_description=f"{service} touché par {ip}",
            new_value={"service": service, "src_ip": ip, "port": port}
        )

    def log_auto_filter_created(self, filter_id, signature_id, src_ip, count):
        """Trace la création auto d'un filtre par le bruit-killer."""
        self.log(
            action="AUTO_FILTER_CREATED",
            action_category="FILTER",
            target_table="alert_filters",
            target_id=filter_id,
            target_description=f"AUTO_NOISE filter for sig={signature_id}, ip={src_ip}",
            new_value={
                "signature_id": signature_id,
                "src_ip": src_ip,
                "alert_count_trigger": count,
            }
        )

    def log_ai_generated(self, alert_id, signature_id, duration_ms, cached=False):
        """Trace une explication IA."""
        self.log(
            action="AI_GENERATED" if not cached else "AI_CACHE_HIT",
            action_category="AI",
            target_table="ai_explanations",
            target_id=alert_id,
            target_description=f"Explication pour alert #{alert_id}",
            new_value={"signature_id": signature_id, "cached": cached},
            duration_ms=duration_ms,
        )

    def log_email_sent(self, recipient, subject, alert_id, success=True, error=None):
        """Trace un envoi d'email."""
        self.log(
            action="EMAIL_SENT" if success else "EMAIL_FAILED",
            action_category="OTHER",
            target_table="email_logs",
            target_id=alert_id,
            target_description=f"To: {recipient[:100]}",
            new_value={"recipient": recipient, "subject": subject[:200]},
            status="SUCCESS" if success else "FAILURE",
            error_message=error,
        )
