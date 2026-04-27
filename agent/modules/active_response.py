"""
Module Active Response — blocage automatique d'IP via iptables.

Comportement :
- Pour les alertes CRITICAL uniquement (configurable)
- Délai configurable avant le blocage effectif (permet d'annuler)
- Durée de blocage configurable (par défaut 1h)
- Déblocage automatique programmé (thread)
- Survie aux redémarrages : au démarrage, l'agent débloque les IPs expirées
- Validation IP avant iptables (pas d'injection)
- Whitelist hardcodée : 127.0.0.1, ::1, IPs des serveurs Wazuh

Toutes les actions sont tracées dans la table blocked_ips.
"""

import subprocess
import threading
import time
import ipaddress
import logging
from datetime import datetime, timedelta

from modules import db

log = logging.getLogger("siem-agent.active_response")


# IPs jamais blockées (sécurité)
HARDCODED_WHITELIST = {"127.0.0.1", "::1", "0.0.0.0"}


class ActiveResponder:
    """
    Gestionnaire de blocage IP automatique.
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")
        self.enabled = config.get_bool("ACTIVE_RESPONSE_ENABLED", True)
        self.delay_sec = config.get_int("ACTIVE_RESPONSE_DELAY_SEC", 300)
        self.duration_sec = config.get_int("ACTIVE_RESPONSE_DURATION_SEC", 3600)
        self.server_ip = config.get("SERVER_IP", "127.0.0.1")

        # Thread tracker pour ne pas bloquer 2 fois
        self._pending = set()  # ips en attente de blocage
        self._lock = threading.Lock()

    # ========================================================================
    # POINT D'ENTRÉE PRINCIPAL
    # ========================================================================

    def handle(self, alert_id, info, signature):
        """
        Décide et déclenche le blocage si applicable.

        Appelé par alert_processor pour les alertes CRITICAL.
        """
        if not self.enabled:
            log.debug("Active Response désactivé — pas de blocage")
            return

        ip = info.get("src_ip")
        if not ip:
            return

        # Validation
        if not self._is_blockable(ip):
            log.debug(f"IP {ip} non blockable (whitelist ou invalide)")
            return

        # Déjà en attente ?
        with self._lock:
            if ip in self._pending:
                log.debug(f"IP {ip} déjà en attente de blocage")
                return
            self._pending.add(ip)

        # Lancer le thread de blocage retardé
        thread = threading.Thread(
            target=self._delayed_block,
            args=(ip, alert_id, signature),
            daemon=True,
            name=f"block-{ip}"
        )
        thread.start()

        log.warning(
            f"Active Response : IP {ip} sera blockée dans {self.delay_sec}s "
            f"(durée {self.duration_sec}s) — alert #{alert_id}"
        )

    # ========================================================================
    # BLOCAGE RETARDÉ (THREAD)
    # ========================================================================

    def _delayed_block(self, ip, alert_id, signature):
        """Attend delay_sec puis bloque effectivement."""
        try:
            time.sleep(self.delay_sec)

            # Vérifier que l'admin n'a pas annulé entre temps
            # (par exemple si l'alerte a été marquée FALSE_POSITIVE)
            if not self._should_still_block(alert_id):
                log.info(f"Blocage annulé pour {ip} (alert #{alert_id} résolue/FP)")
                with self._lock:
                    self._pending.discard(ip)
                return

            self.block_ip(
                ip=ip,
                alert_id=alert_id,
                signature_id=signature["id"],
                reason=f"Active Response auto pour signature #{signature['id']} ({signature['severity']})",
                blocked_by="AGENT",
                duration_sec=self.duration_sec,
            )
        finally:
            with self._lock:
                self._pending.discard(ip)

    def _should_still_block(self, alert_id):
        """Vérifie que l'alerte n'a pas été résolue ou marquée FP entre-temps."""
        try:
            row = db.execute_with_retry(
                self.db_path,
                "SELECT status FROM alerts WHERE id = ?",
                (alert_id,),
                fetch_one=True
            )
            if not row:
                return False
            return row["status"] not in ("RESOLVED", "FALSE_POSITIVE", "IGNORED")
        except Exception:
            # En cas de doute, on bloque quand même (sécurité par défaut)
            return True

    # ========================================================================
    # BLOCAGE EFFECTIF (peut être appelé manuellement aussi)
    # ========================================================================

    def block_ip(self, ip, alert_id=None, signature_id=None, reason=None,
                 blocked_by="AGENT", blocked_by_user=None, duration_sec=None):
        """
        Bloque une IP via iptables et enregistre dans blocked_ips.

        Args:
            ip : adresse IP
            alert_id : id de l'alerte source (optionnel)
            signature_id : id de la signature (optionnel)
            reason : raison du blocage (texte libre)
            blocked_by : 'AGENT' / 'MANUAL' / 'HONEYPOT' / 'THREAT_INTEL'
            blocked_by_user : id user si MANUAL
            duration_sec : durée du blocage (None = permanent)

        Returns: True si succès, False sinon
        """
        if not self._is_blockable(ip):
            return False

        # 1. Vérifier qu'elle n'est pas déjà bloquée
        if self.is_blocked(ip):
            log.info(f"IP {ip} déjà bloquée — extension de la durée seulement")
            self._extend_block(ip, duration_sec)
            return True

        # 2. iptables
        iptables_rule = f"iptables -I INPUT -s {ip} -j DROP"
        try:
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                timeout=15,
                text=True
            )
            if result.returncode != 0:
                log.error(f"iptables échec : {result.stderr.strip()}")
                return False
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            log.error(f"Erreur iptables : {e}")
            return False

        # 3. Enregistrer dans blocked_ips
        expires_at = None
        if duration_sec:
            expires_at = (datetime.now() + timedelta(seconds=duration_sec)).isoformat()

        try:
            severity = "HIGH" if blocked_by == "AGENT" else "CRITICAL" if blocked_by == "HONEYPOT" else "MEDIUM"
            db.execute_with_retry(
                self.db_path,
                """
                INSERT INTO blocked_ips (
                    ip_address, alert_id, signature_id, reason, severity,
                    blocked_by, blocked_by_user, blocked_at, expires_at,
                    is_active, iptables_rule
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, 1, ?)
                """,
                (
                    ip, alert_id, signature_id, reason or "Blocage manuel",
                    severity, blocked_by, blocked_by_user,
                    expires_at, iptables_rule
                )
            )
        except Exception as e:
            log.error(f"Erreur insertion blocked_ips : {e}")
            # On ne fait pas rollback iptables : mieux vaut bloquer sans trace que pas bloquer

        log.warning(f"✓ IP {ip} BLOQUÉE (durée: {duration_sec}s, raison: {reason})")

        # 4. Programmer le déblocage automatique
        if duration_sec:
            unblock_thread = threading.Thread(
                target=self._delayed_unblock,
                args=(ip, duration_sec),
                daemon=True,
                name=f"unblock-{ip}"
            )
            unblock_thread.start()

        return True

    # ========================================================================
    # DÉBLOCAGE
    # ========================================================================

    def _delayed_unblock(self, ip, after_sec):
        """Attend puis débloque."""
        time.sleep(after_sec)
        self.unblock_ip(ip, reason="Expiration auto")

    def unblock_ip(self, ip, reason="Manuel", unblocked_by_user=None):
        """Retire la règle iptables et marque le blocage inactif."""
        try:
            # Retirer la règle (peut échouer si déjà retirée — c'est OK)
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                timeout=10,
            )

            # Marquer inactif en BDD
            db.execute_with_retry(
                self.db_path,
                """
                UPDATE blocked_ips
                SET is_active = 0,
                    unblocked_at = CURRENT_TIMESTAMP,
                    unblocked_by = ?,
                    unblock_reason = ?
                WHERE ip_address = ? AND is_active = 1
                """,
                (unblocked_by_user, reason, ip)
            )

            log.info(f"✓ IP {ip} DÉBLOQUÉE ({reason})")
            return True
        except Exception as e:
            log.error(f"Erreur déblocage {ip} : {e}")
            return False

    def _extend_block(self, ip, duration_sec):
        """Prolonge la durée de blocage d'une IP déjà bloquée."""
        if not duration_sec:
            return
        new_expires = (datetime.now() + timedelta(seconds=duration_sec)).isoformat()
        try:
            db.execute_with_retry(
                self.db_path,
                """
                UPDATE blocked_ips
                SET expires_at = ?
                WHERE ip_address = ? AND is_active = 1
                """,
                (new_expires, ip)
            )
        except Exception as e:
            log.debug(f"Erreur extend block : {e}")

    # ========================================================================
    # HELPERS
    # ========================================================================

    def _is_blockable(self, ip):
        """Valide qu'une IP est blockable (whitelist + format)."""
        if not ip:
            return False
        if ip in HARDCODED_WHITELIST:
            return False
        if ip == self.server_ip:
            log.warning(f"Tentative de blocage de l'IP du serveur ! Ignoré : {ip}")
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback:
                return False
            return True
        except ValueError:
            log.error(f"IP invalide ignorée : {ip!r}")
            return False

    def is_blocked(self, ip):
        """Vérifie si une IP est actuellement bloquée."""
        try:
            row = db.execute_with_retry(
                self.db_path,
                """
                SELECT id FROM blocked_ips
                WHERE ip_address = ? AND is_active = 1
                LIMIT 1
                """,
                (ip,),
                fetch_one=True
            )
            return row is not None
        except Exception:
            return False

    # ========================================================================
    # RESTAURATION AU DÉMARRAGE (survie aux redémarrages)
    # ========================================================================

    def cleanup_expired_on_startup(self):
        """
        À appeler au démarrage de l'agent.

        Pour chaque blocage avec expires_at passé : retirer la règle iptables
        (qui n'existe sûrement plus après un reboot mais on fait propre).
        Pour les blocages permanents : réactiver la règle iptables si elle
        n'existe plus.
        """
        try:
            # 1. Marquer expirés
            db.execute_with_retry(
                self.db_path,
                """
                UPDATE blocked_ips
                SET is_active = 0,
                    unblocked_at = CURRENT_TIMESTAMP,
                    unblock_reason = 'Expiration automatique au démarrage agent'
                WHERE is_active = 1
                  AND expires_at IS NOT NULL
                  AND expires_at <= CURRENT_TIMESTAMP
                """
            )

            # 2. Restaurer les règles iptables pour les blocages encore actifs
            rows = db.execute_with_retry(
                self.db_path,
                "SELECT ip_address FROM blocked_ips WHERE is_active = 1",
                (),
                fetch_all=True
            ) or []

            restored = 0
            for row in rows:
                ip = row["ip_address"]
                if not self._is_blockable(ip):
                    continue
                # Vérifier si la règle existe déjà (idempotent)
                check = subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
                if check.returncode != 0:
                    # Pas de règle → l'ajouter
                    subprocess.run(
                        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=10
                    )
                    restored += 1

            if restored:
                log.info(f"Restauration au démarrage : {restored} règles iptables réinjectées")
        except Exception as e:
            log.error(f"Erreur cleanup_expired_on_startup : {e}")
