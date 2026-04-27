"""
Module Bruit-Killer — détection automatique des alert storms (Mécanisme 3 du CDC).

À exécuter périodiquement (toutes les heures via cron ou systemd timer).

Fonctionnement :
1. Détecte les couples (signature, src_ip) qui dépassent NOISE_KILLER_THRESHOLD
   alertes dans la fenêtre NOISE_KILLER_WINDOW_HOURS
2. Pour chaque couple détecté, crée un filtre alert_filters AUTO_NOISE
   avec expires_at = +NOISE_KILLER_FILTER_DURATION_HOURS
3. Le filtre fait un DOWNGRADE pour éviter de spammer le dashboard
4. Une notification est créée pour les admins
5. L'agent recharge automatiquement son cache de filtres au prochain cycle
"""

import json
import logging
import uuid
from datetime import datetime, timedelta

from modules import db
from modules.correlator import Correlator

log = logging.getLogger("siem-agent.noise_killer")


class NoiseKiller:
    """
    Détecteur d'alert storms.

    Peut être lancé en mode :
    - Standalone : python3 -m modules.noise_killer (via cron)
    - Embedded : appelé par l'agent toutes les heures
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")
        self.threshold = config.get_int("NOISE_KILLER_THRESHOLD", 100)
        self.window_hours = config.get_int("NOISE_KILLER_WINDOW_HOURS", 1)
        self.filter_duration_hours = config.get_int(
            "NOISE_KILLER_FILTER_DURATION_HOURS", 24
        )

    # ========================================================================
    # POINT D'ENTRÉE PRINCIPAL
    # ========================================================================

    def run(self):
        """
        Exécute une passe de détection.

        Returns: dict de stats
            {"detected": int, "filters_created": int, "filters_skipped": int}
        """
        log.info(
            f"Bruit-killer : recherche couples >= {self.threshold} alertes "
            f"sur {self.window_hours}h"
        )

        stats = {"detected": 0, "filters_created": 0, "filters_skipped": 0}

        # 1. Détecter
        correlator = Correlator(self.config)
        candidates = correlator.get_high_volume_signatures(
            window_hours=self.window_hours,
            threshold=self.threshold
        )
        stats["detected"] = len(candidates)

        if not candidates:
            log.info("Aucun bruit détecté")
            return stats

        log.warning(f"⚠ {len(candidates)} couple(s) bruyants détectés")

        # 2. Créer un filtre par couple
        for c in candidates:
            try:
                signature_id = c["signature_id"]
                src_ip = c["src_ip"]
                count = c["nb"]

                # Vérifier qu'il n'existe pas déjà un filtre AUTO_NOISE actif
                # pour ce couple
                existing = self._find_existing_auto_filter(signature_id, src_ip)
                if existing:
                    # Prolonger sa durée plutôt que créer un doublon
                    self._extend_filter(existing["id"])
                    stats["filters_skipped"] += 1
                    log.info(
                        f"Filtre AUTO_NOISE déjà actif pour sig={signature_id} ip={src_ip} — prolongé"
                    )
                    continue

                # Créer le filtre
                filter_id = self._create_auto_filter(signature_id, src_ip, count)
                if filter_id:
                    stats["filters_created"] += 1
                    log.warning(
                        f"✓ Filtre AUTO_NOISE #{filter_id} créé : sig={signature_id} "
                        f"ip={src_ip} ({count} alertes en {self.window_hours}h)"
                    )
                    # Notifier les admins
                    self._notify_admins(filter_id, signature_id, src_ip, count)

            except Exception as e:
                log.error(f"Erreur traitement couple {c} : {e}")

        log.info(f"Bruit-killer terminé : {stats}")
        return stats

    # ========================================================================
    # CRÉATION DE FILTRE
    # ========================================================================

    def _find_existing_auto_filter(self, signature_id, src_ip):
        """Cherche un filtre AUTO_NOISE actif pour ce couple."""
        try:
            row = db.execute_with_retry(
                self.db_path,
                """
                SELECT id, expires_at FROM alert_filters
                WHERE signature_id = ?
                  AND src_ip = ?
                  AND filter_type = 'AUTO_NOISE'
                  AND is_active = 1
                  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                LIMIT 1
                """,
                (signature_id, src_ip),
                fetch_one=True
            )
            return dict(row) if row else None
        except Exception as e:
            log.debug(f"Erreur recherche filtre existant : {e}")
            return None

    def _create_auto_filter(self, signature_id, src_ip, count):
        """Crée un filtre AUTO_NOISE avec expires_at."""
        expires = (
            datetime.now() + timedelta(hours=self.filter_duration_hours)
        ).isoformat()

        reason = (
            f"Auto-créé par bruit-killer : {count} alertes en {self.window_hours}h "
            f"(seuil={self.threshold}). Durée filtre={self.filter_duration_hours}h."
        )

        name = f"AUTO-KILL: storm sig={signature_id} ip={src_ip}"

        try:
            return db.execute_with_retry(
                self.db_path,
                """
                INSERT INTO alert_filters (
                    filter_uuid, name, signature_id, src_ip,
                    action, downgrade_to, filter_type, reason,
                    is_active, expires_at,
                    metadata
                ) VALUES (
                    ?, ?, ?, ?,
                    'DOWNGRADE', 'LOW', 'AUTO_NOISE', ?,
                    1, ?,
                    ?
                )
                """,
                (
                    str(uuid.uuid4()),
                    name[:200],
                    signature_id,
                    src_ip,
                    reason,
                    expires,
                    json.dumps({
                        "alert_count_at_creation": count,
                        "window_hours": self.window_hours,
                        "threshold": self.threshold,
                    }),
                )
            )
        except Exception as e:
            log.error(f"Erreur création filtre AUTO_NOISE : {e}")
            return None

    def _extend_filter(self, filter_id):
        """Prolonge un filtre existant."""
        new_expires = (
            datetime.now() + timedelta(hours=self.filter_duration_hours)
        ).isoformat()
        try:
            db.execute_with_retry(
                self.db_path,
                "UPDATE alert_filters SET expires_at = ? WHERE id = ?",
                (new_expires, filter_id)
            )
        except Exception as e:
            log.debug(f"Erreur extend filter : {e}")

    # ========================================================================
    # NOTIFICATION ADMINS
    # ========================================================================

    def _notify_admins(self, filter_id, signature_id, src_ip, count):
        """Insère une notification dashboard pour les admins."""
        try:
            admins = db.execute_with_retry(
                self.db_path,
                """
                SELECT u.id FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.is_active = 1
                  AND u.deleted_at IS NULL
                  AND r.code = 'ADMIN'
                """,
                (),
                fetch_all=True
            )

            if not admins:
                return

            title = f"Bruit-killer : storm détecté pour signature #{signature_id}"
            message = (
                f"L'IP {src_ip} a généré {count} alertes en {self.window_hours}h "
                f"sur la signature #{signature_id}. Un filtre AUTO_NOISE a été créé "
                f"automatiquement (durée {self.filter_duration_hours}h). "
                f"Investiguer pour identifier la cause."
            )

            for admin in admins:
                db.execute_with_retry(
                    self.db_path,
                    """
                    INSERT INTO notifications (
                        notification_uuid, user_id, title, message, severity,
                        notification_type, is_read
                    ) VALUES (?, ?, ?, ?, 'MEDIUM', 'SYSTEM', 0)
                    """,
                    (str(uuid.uuid4()), admin["id"], title, message)
                )
        except Exception as e:
            log.error(f"Erreur notification bruit-killer : {e}")


# ============================================================================
# ENTRY POINT (lancement standalone via cron)
# ============================================================================

def main():
    """Point d'entrée pour exécution standalone via cron."""
    import sys
    sys.path.insert(0, "/opt/siem-africa-agent")

    from modules.config import get_config
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    )

    config = get_config()
    nk = NoiseKiller(config)
    stats = nk.run()

    print(f"Stats : {stats}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
