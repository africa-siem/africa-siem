"""
Module de notifications.

Gère 2 canaux :
1. Email SMTP — alertes critiques envoyées aux admins
2. Notifications dashboard — insertions dans la table notifications

Caractéristiques :
- Anti-spam interne via dedup_key (hash signature+IP+heure arrondie)
- Rate-limiting par fenêtre temporelle (config EMAIL_DEDUP_WINDOW_MIN)
- Bilingue FR/EN (selon config LANG)
- Logging complet dans email_logs
- Filtrage par sévérité minimum (config MIN_SEVERITY_FOR_EMAIL)
- Support Postfix local OU relay SMTP externe (Gmail App Password)
"""

import smtplib
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from modules import db

log = logging.getLogger("siem-agent.notifier")


# Hiérarchie des sévérités (pour filtrer par MIN_SEVERITY_FOR_EMAIL)
SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class Notifier:
    """
    Notifieur multi-canal pour les alertes.
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")

        # Config SMTP
        self.smtp_host = config.get("SMTP_HOST", "localhost")
        self.smtp_port = config.get_int("SMTP_PORT", 25)
        self.smtp_user = config.get("SMTP_USER", "")
        self.smtp_password = config.get("SMTP_PASSWORD", "")
        self.smtp_use_tls = config.get_bool("SMTP_USE_TLS", True)
        self.smtp_from = config.get("SMTP_FROM", "siem-africa@localhost")

        # Destinataires
        self.alert_email = config.get("ALERT_EMAIL", "")

        # Filtres
        self.lang = config.get("LANG", "fr")
        self.min_severity = config.get("MIN_SEVERITY_FOR_EMAIL", "HIGH").upper()
        self.dedup_window_min = config.get_int("EMAIL_DEDUP_WINDOW_MIN", 15)
        self.server_ip = config.get("SERVER_IP", "127.0.0.1")
        self.dashboard_url = config.get("DASHBOARD_URL", "http://127.0.0.1:8000")

    # ========================================================================
    # POINT D'ENTRÉE PRINCIPAL
    # ========================================================================

    def notify(self, alert_id, signature, info, enriched_data):
        """
        Envoie les notifications appropriées pour une nouvelle alerte.

        - Insère systématiquement une notification in-app (dashboard)
        - Envoie un email si sévérité >= MIN_SEVERITY_FOR_EMAIL
        - Anti-spam via dedup_key
        """
        # 1. Notification dashboard (toujours)
        try:
            self._insert_dashboard_notification(alert_id, signature, info)
        except Exception as e:
            log.error(f"Erreur notification dashboard : {e}")

        # 2. Email (seulement si sévérité suffisante)
        severity = signature.get("severity", "MEDIUM")
        if not self._should_email(severity):
            log.debug(
                f"Pas d'email : severity={severity} < min={self.min_severity}"
            )
            return

        # 3. Vérifier anti-spam (dedup)
        dedup_key = self._make_dedup_key(signature["id"], info.get("src_ip"))
        if self._is_recent_email(dedup_key):
            log.info(
                f"Email dédupliqué (envoyé il y a < {self.dedup_window_min} min) : {dedup_key[:16]}"
            )
            return

        # 4. Envoyer
        try:
            self._send_email(alert_id, signature, info, enriched_data, dedup_key)
        except Exception as e:
            log.error(f"Erreur envoi email : {e}")

    # ========================================================================
    # NOTIFICATION DASHBOARD
    # ========================================================================

    def _insert_dashboard_notification(self, alert_id, signature, info):
        """Insère une notification visible dans le dashboard."""
        # On notifie tous les admins actifs
        admins = db.execute_with_retry(
            self.db_path,
            """
            SELECT u.id FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.is_active = 1
              AND u.deleted_at IS NULL
              AND r.code IN ('ADMIN', 'ANALYST')
            """,
            (),
            fetch_all=True
        )

        if not admins:
            log.debug("Aucun admin/analyst actif — notification dashboard ignorée")
            return

        title = f"[{signature['severity']}] {signature['name'][:200]}"
        message = (
            f"{signature.get('description_fr') or signature.get('description', '')[:300]}\n\n"
            f"IP source : {info.get('src_ip', 'inconnue')}"
        )
        action_url = f"{self.dashboard_url}/alerts/{alert_id}"

        for admin in admins:
            try:
                db.execute_with_retry(
                    self.db_path,
                    """
                    INSERT INTO notifications (
                        notification_uuid, user_id, title, message, severity,
                        notification_type, related_alert_id, action_url, is_read
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        str(uuid.uuid4()),
                        admin["id"],
                        title,
                        message,
                        signature["severity"],
                        "ALERT",
                        alert_id,
                        action_url,
                    )
                )
            except Exception as e:
                log.debug(f"Erreur notif user #{admin['id']} : {e}")

    # ========================================================================
    # EMAIL
    # ========================================================================

    def _should_email(self, severity):
        """Décide si la sévérité justifie un email."""
        if not self.alert_email or not self.smtp_host:
            return False
        cur_rank = SEVERITY_RANK.get(severity.upper(), 0)
        min_rank = SEVERITY_RANK.get(self.min_severity, 3)
        return cur_rank >= min_rank

    def _make_dedup_key(self, signature_id, src_ip):
        """Génère une clé de dédup basée sur signature + IP + tranche horaire."""
        # Tranche de dedup_window_min minutes
        slot = int(datetime.now().timestamp() // (self.dedup_window_min * 60))
        raw = f"{signature_id}|{src_ip or 'none'}|{slot}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _is_recent_email(self, dedup_key):
        """Vérifie si un email avec la même dedup_key a été envoyé récemment."""
        cutoff = (datetime.now() - timedelta(minutes=self.dedup_window_min)).isoformat()
        try:
            row = db.execute_with_retry(
                self.db_path,
                """
                SELECT id FROM email_logs
                WHERE dedup_key = ?
                  AND sent_at >= ?
                  AND status IN ('SENT', 'DELIVERED', 'PENDING')
                LIMIT 1
                """,
                (dedup_key, cutoff),
                fetch_one=True
            )
            return row is not None
        except Exception as e:
            log.debug(f"Erreur check dedup : {e}")
            return False

    def _send_email(self, alert_id, signature, info, enriched_data, dedup_key):
        """Envoie effectivement l'email + log dans email_logs."""
        recipients = [e.strip() for e in self.alert_email.split(",") if e.strip()]
        if not recipients:
            log.warning("ALERT_EMAIL vide — aucun destinataire")
            return

        # Construction du message
        subject = self._build_subject(signature, info)
        body_html, body_text = self._build_body(alert_id, signature, info, enriched_data)

        # Log PENDING avant envoi
        email_uuid = str(uuid.uuid4())
        log_id = self._log_email(
            email_uuid, recipients[0], subject, body_html, body_text,
            alert_id, signature["severity"], dedup_key, status="PENDING"
        )

        try:
            self._smtp_send(recipients, subject, body_html, body_text)
            self._update_email_status(log_id, "SENT")
            log.info(f"Email envoyé à {', '.join(recipients)} : {subject[:60]}")
        except Exception as e:
            err_msg = str(e)[:500]
            self._update_email_status(log_id, "FAILED", error=err_msg)
            log.error(f"Échec envoi email : {err_msg}")
            raise

    def _smtp_send(self, recipients, subject, body_html, body_text):
        """Connexion SMTP et envoi du mail."""
        msg = MIMEMultipart("alternative")
        msg["From"] = self.smtp_from
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject

        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        # Connexion
        if self.smtp_port == 465:
            # SSL implicite
            server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
            server.ehlo()
            if self.smtp_use_tls:
                server.starttls()
                server.ehlo()

        try:
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            server.sendmail(self.smtp_from, recipients, msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                pass

    # ========================================================================
    # CONSTRUCTION DU MESSAGE
    # ========================================================================

    def _build_subject(self, signature, info):
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
        icon = icons.get(signature["severity"], "⚠")
        if self.lang == "en":
            return f"[SIEM Africa] {icon} {signature['severity']} — {signature['name'][:80]}"
        return f"[SIEM Africa] {icon} Alerte {signature['severity']} — {signature['name'][:80]}"

    def _build_body(self, alert_id, signature, info, enriched_data):
        """Construit le corps HTML + texte de l'email."""
        is_fr = self.lang == "fr"

        # Données
        sig_name = signature.get("name", "Alerte")
        sig_desc = signature.get("description_fr") if is_fr else signature.get("description")
        sig_desc = sig_desc or signature.get("description", "")
        remediation = signature.get("remediation_fr") if is_fr else signature.get("remediation")
        remediation = remediation or ""
        severity = signature.get("severity", "MEDIUM")
        src_ip = info.get("src_ip", "inconnue")
        dst_ip = info.get("dst_ip", "")

        # Enrichissement
        enriched = enriched_data or {}
        mitre = enriched.get("mitre", {})
        local_stats = enriched.get("local_stats", {})

        # URL dashboard
        alert_url = f"{self.dashboard_url}/alerts/{alert_id}"

        # === Version texte ===
        if is_fr:
            text = f"""SIEM AFRICA - ALERTE DE SÉCURITÉ
{'=' * 60}

Sévérité   : {severity}
Type       : {sig_name}
Source IP  : {src_ip}
Destination: {dst_ip}
Date       : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}

DESCRIPTION
{sig_desc}

"""
            if mitre:
                text += f"MITRE ATT&CK\n"
                text += f"  Technique : {mitre.get('technique_id')} - {mitre.get('technique_name')}\n"
                text += f"  Tactique  : {mitre.get('tactic_id')} - {mitre.get('tactic_name')}\n\n"

            if local_stats:
                text += "CONTEXTE LOCAL\n"
                if local_stats.get("alerts_24h_for_ip"):
                    text += f"  Alertes de cette IP en 24h : {local_stats['alerts_24h_for_ip']}\n"
                if local_stats.get("is_recurrent_attacker"):
                    text += f"  ⚠ Cette IP est un attaquant récurrent\n"
                if local_stats.get("has_been_blocked"):
                    text += f"  ⚠ Cette IP a déjà été bloquée\n"
                text += "\n"

            if remediation:
                text += f"REMÉDIATION\n{remediation}\n\n"

            text += f"VOIR DANS LE DASHBOARD\n{alert_url}\n\n"
            text += "—\nSIEM Africa | github.com/africa-siem/africa-siem\n"

        else:  # English
            text = f"""SIEM AFRICA - SECURITY ALERT
{'=' * 60}

Severity   : {severity}
Type       : {sig_name}
Source IP  : {src_ip}
Destination: {dst_ip}
Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

DESCRIPTION
{sig_desc}

"""
            if mitre:
                text += f"MITRE ATT&CK\n"
                text += f"  Technique : {mitre.get('technique_id')} - {mitre.get('technique_name')}\n"
                text += f"  Tactic    : {mitre.get('tactic_id')} - {mitre.get('tactic_name')}\n\n"

            if local_stats:
                text += "LOCAL CONTEXT\n"
                if local_stats.get("alerts_24h_for_ip"):
                    text += f"  Alerts from this IP in 24h: {local_stats['alerts_24h_for_ip']}\n"
                if local_stats.get("is_recurrent_attacker"):
                    text += f"  ⚠ Recurrent attacker\n"
                if local_stats.get("has_been_blocked"):
                    text += f"  ⚠ This IP has been blocked before\n"
                text += "\n"

            if remediation:
                text += f"REMEDIATION\n{remediation}\n\n"

            text += f"VIEW IN DASHBOARD\n{alert_url}\n\n"
            text += "—\nSIEM Africa | github.com/africa-siem/africa-siem\n"

        # === Version HTML (simple, lisible) ===
        sev_color = {
            "CRITICAL": "#E74C3C",
            "HIGH": "#E67E22",
            "MEDIUM": "#F39C12",
            "LOW": "#27AE60",
            "INFO": "#3498DB",
        }.get(severity, "#95A5A6")

        # Échapper le HTML
        import html as html_mod
        sig_name_h = html_mod.escape(sig_name)
        sig_desc_h = html_mod.escape(sig_desc).replace("\n", "<br>")
        src_ip_h = html_mod.escape(src_ip)
        dst_ip_h = html_mod.escape(dst_ip)
        remediation_h = html_mod.escape(remediation).replace("\n", "<br>")

        title_label = "ALERTE DE SÉCURITÉ" if is_fr else "SECURITY ALERT"
        sev_label = "Sévérité" if is_fr else "Severity"
        type_label = "Type"
        src_label = "IP source"
        dst_label = "Destination"
        date_label = "Date"
        desc_label = "Description"
        rem_label = "Remédiation" if is_fr else "Remediation"
        view_label = "Voir l'alerte dans le dashboard" if is_fr else "View alert in dashboard"

        html = f"""<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <div style="background: {sev_color}; color: white; padding: 20px; text-align: center;">
      <h1 style="margin: 0; font-size: 22px;">SIEM AFRICA</h1>
      <p style="margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;">{title_label}</p>
    </div>
    <div style="padding: 25px;">
      <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
        <tr><td style="padding: 8px 0; color: #666;"><b>{sev_label}</b></td><td style="padding: 8px 0;"><span style="background: {sev_color}; color: white; padding: 3px 10px; border-radius: 4px; font-size: 13px;">{severity}</span></td></tr>
        <tr><td style="padding: 8px 0; color: #666;"><b>{type_label}</b></td><td style="padding: 8px 0;">{sig_name_h}</td></tr>
        <tr><td style="padding: 8px 0; color: #666;"><b>{src_label}</b></td><td style="padding: 8px 0; font-family: monospace;">{src_ip_h}</td></tr>"""

        if dst_ip:
            html += f'<tr><td style="padding: 8px 0; color: #666;"><b>{dst_label}</b></td><td style="padding: 8px 0; font-family: monospace;">{dst_ip_h}</td></tr>'

        html += f'<tr><td style="padding: 8px 0; color: #666;"><b>{date_label}</b></td><td style="padding: 8px 0;">{datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</td></tr>'

        html += f"""
      </table>
      <h3 style="color: #2C3E50; border-bottom: 2px solid {sev_color}; padding-bottom: 8px;">{desc_label}</h3>
      <p style="color: #555; line-height: 1.6;">{sig_desc_h}</p>
"""

        if mitre:
            mitre_label = "MITRE ATT&CK"
            html += f"""
      <h3 style="color: #2C3E50; border-bottom: 2px solid {sev_color}; padding-bottom: 8px;">{mitre_label}</h3>
      <p>
        <b>Technique:</b> <a href="{mitre.get('url', '#')}" style="color: {sev_color};">{html_mod.escape(mitre.get('technique_id', ''))} — {html_mod.escape(mitre.get('technique_name', ''))}</a><br>
        <b>{'Tactique' if is_fr else 'Tactic'}:</b> {html_mod.escape(mitre.get('tactic_id', ''))} — {html_mod.escape(mitre.get('tactic_name', ''))}
      </p>
"""

        if remediation:
            html += f"""
      <h3 style="color: #2C3E50; border-bottom: 2px solid {sev_color}; padding-bottom: 8px;">{rem_label}</h3>
      <div style="background: #f9f9f9; border-left: 3px solid {sev_color}; padding: 12px; color: #555; line-height: 1.6;">
        {remediation_h}
      </div>
"""

        html += f"""
      <div style="text-align: center; margin: 30px 0 10px 0;">
        <a href="{alert_url}" style="background: {sev_color}; color: white; padding: 12px 28px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">{view_label}</a>
      </div>
    </div>
    <div style="background: #ECF0F1; padding: 15px; text-align: center; color: #888; font-size: 12px;">
      SIEM Africa · github.com/africa-siem/africa-siem
    </div>
  </div>
</body></html>"""

        return html, text

    # ========================================================================
    # LOGGING DANS email_logs
    # ========================================================================

    def _log_email(self, email_uuid, recipient, subject, body_html, body_text,
                   alert_id, severity, dedup_key, status="PENDING"):
        """Insère un log dans email_logs."""
        try:
            sql = """
                INSERT INTO email_logs (
                    email_uuid, recipient_email, subject, body_html, body_text,
                    email_type, priority, related_alert_id, status, dedup_key,
                    smtp_provider, queued_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            priority = "URGENT" if severity == "CRITICAL" else "HIGH" if severity == "HIGH" else "NORMAL"
            email_type = "CRITICAL_ALERT" if severity in ("CRITICAL", "HIGH") else "OTHER"
            return db.execute_with_retry(
                self.db_path,
                sql,
                (
                    email_uuid, recipient, subject[:500], body_html[:50000], body_text[:10000],
                    email_type, priority, alert_id, status, dedup_key,
                    self.smtp_host
                )
            )
        except Exception as e:
            log.error(f"Erreur log email : {e}")
            return None

    def _update_email_status(self, log_id, status, error=None):
        """Met à jour le statut d'un email_log."""
        if not log_id:
            return
        try:
            if error:
                db.execute_with_retry(
                    self.db_path,
                    """
                    UPDATE email_logs
                    SET status = ?, error_message = ?, sent_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, error, log_id)
                )
            else:
                db.execute_with_retry(
                    self.db_path,
                    """
                    UPDATE email_logs
                    SET status = ?, sent_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, log_id)
                )
        except Exception as e:
            log.debug(f"Erreur update email_log : {e}")
