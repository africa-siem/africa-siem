"""
Module de corrélation des alertes.

Évite la création de doublons dans la table `alerts` quand une même attaque
génère plusieurs événements en peu de temps. Au lieu de créer N alertes,
on en crée une seule avec event_count = N et last_seen mis à jour.

Stratégie :
    - Quand une alerte arrive, on cherche dans la BDD si une alerte
      "compatible" existe déjà dans la fenêtre de corrélation
    - Critères de compatibilité (TOUT doit matcher) :
        * même signature_id
        * même src_ip
        * même asset (si présent)
        * status NEW ou ACKNOWLEDGED ou INVESTIGATING (pas RESOLVED/FP)
        * last_seen dans la fenêtre temporelle
    - Si trouvée, on UPDATE event_count et last_seen au lieu d'INSERT

Cela réduit drastiquement le bruit visuel dans le dashboard pour les
attaques de type brute force, scan, flood, etc.
"""

import logging
from datetime import datetime

from modules import db

log = logging.getLogger("siem-agent.correlator")


class Correlator:
    """
    Corrélateur d'alertes basé sur la BDD.

    Différent du cache court-terme du processor (10s anti-doublon de lecture).
    Ici on cherche une alerte EXISTANTE en BDD à fusionner.
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")
        self.window_sec = config.get_int("CORRELATION_WINDOW_SEC", 60)

    # ========================================================================
    # RECHERCHE D'ALERTE EXISTANTE
    # ========================================================================

    def find_existing(self, info, signature):
        """
        Cherche une alerte existante compatible dans la fenêtre temporelle.

        Returns:
            int | None : id de l'alerte existante, ou None si rien trouvé
        """
        if not info.get("src_ip"):
            # Sans src_ip on ne peut pas corréler de façon fiable
            return None

        sql = """
            SELECT id, event_count, last_seen
            FROM alerts
            WHERE signature_id = ?
              AND src_ip = ?
              AND status IN ('NEW', 'ACKNOWLEDGED', 'INVESTIGATING')
              AND last_seen >= datetime('now', ?)
            ORDER BY last_seen DESC
            LIMIT 1
        """
        params = (
            signature["id"],
            info["src_ip"],
            f"-{self.window_sec} seconds",
        )

        try:
            row = db.execute_with_retry(self.db_path, sql, params, fetch_one=True)
            if row:
                log.debug(
                    f"Corrélation trouvée : alerte #{row['id']} "
                    f"(event_count={row['event_count']})"
                )
                return row["id"]
        except Exception as e:
            log.error(f"Erreur recherche corrélation : {e}")

        return None

    # ========================================================================
    # FUSION DANS UNE ALERTE EXISTANTE
    # ========================================================================

    def merge_into(self, existing_alert_id, info):
        """
        Met à jour une alerte existante : incrémente event_count et
        update last_seen.

        Args:
            existing_alert_id : id de l'alerte à mettre à jour
            info : dict de l'événement entrant (pour timestamp éventuel)
        """
        last_seen = info.get("timestamp") or datetime.now().isoformat()

        sql = """
            UPDATE alerts
            SET event_count = event_count + 1,
                last_seen = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """

        try:
            db.execute_with_retry(self.db_path, sql, (last_seen, existing_alert_id))
            log.debug(f"Alerte #{existing_alert_id} mise à jour (event_count++)")
        except Exception as e:
            log.error(f"Erreur fusion alerte #{existing_alert_id} : {e}")

    # ========================================================================
    # NETTOYAGE PÉRIODIQUE (utilitaire pour le bruit-killer)
    # ========================================================================

    def get_high_volume_signatures(self, window_hours=1, threshold=100):
        """
        Détecte les couples (signature, src_ip) qui dépassent le seuil
        d'alertes dans la fenêtre donnée.

        Utilisé par noise_killer.py pour créer des filtres temporaires.

        Returns:
            list de dicts : [{"signature_id":..., "src_ip":..., "count":...}, ...]
        """
        sql = """
            SELECT signature_id, src_ip, COUNT(*) AS nb
            FROM alerts
            WHERE created_at >= datetime('now', ?)
              AND status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
              AND src_ip IS NOT NULL
            GROUP BY signature_id, src_ip
            HAVING nb >= ?
            ORDER BY nb DESC
        """
        params = (f"-{window_hours} hours", threshold)

        try:
            rows = db.execute_with_retry(self.db_path, sql, params, fetch_all=True)
            return [dict(r) for r in (rows or [])]
        except Exception as e:
            log.error(f"Erreur get_high_volume_signatures : {e}")
            return []
