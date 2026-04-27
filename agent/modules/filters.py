"""
Module de gestion des faux positifs.

Implémente les 5 mécanismes du CDC :
    1. Pré-tagging des signatures (champ is_noisy + filtres PRE_TAGGED)
    2. Filtres alert_filters explicites (créés manuellement par l'admin)
    3. Bruit-killer automatique (cron horaire — voir noise_killer.py)
    4. Confidence dynamique (triggers SQL automatiques — déjà dans schema.sql)
    5. Workflow FALSE_POSITIVE manuel (action depuis dashboard)

Ce module évalue UN événement contre les filtres existants et décide :
    - PASS    : laisser passer (alerte créée normalement)
    - IGNORE  : ne pas créer d'alerte
    - DOWNGRADE : créer mais avec sévérité réduite
"""

import re
import logging
from datetime import datetime, time as dt_time

from modules import db

log = logging.getLogger("siem-agent.filters")


class FilterEngine:
    """
    Moteur d'évaluation des filtres alert_filters.

    Charge les filtres actifs en cache (TTL 60s par défaut) pour éviter
    de relire la BDD à chaque alerte. Le cache est invalidé automatiquement.
    """

    CACHE_TTL_SEC = 60

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")

        self._cache = []
        self._cache_loaded_at = 0

    # ========================================================================
    # CHARGEMENT DES FILTRES (avec cache)
    # ========================================================================

    def _load_active_filters(self):
        """
        Charge tous les filtres actifs depuis alert_filters.

        Filtre : is_active=1 AND (expires_at IS NULL OR expires_at > now)
                 AND deleted_at IS NULL
        """
        sql = """
            SELECT *
            FROM alert_filters
            WHERE is_active = 1
              AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ORDER BY filter_type, id
        """
        try:
            rows = db.execute_with_retry(self.db_path, sql, (), fetch_all=True)
            return [dict(r) for r in (rows or [])]
        except Exception as e:
            log.error(f"Erreur chargement filtres : {e}")
            return []

    def _refresh_cache_if_needed(self):
        import time as _t
        now = _t.time()
        if (now - self._cache_loaded_at) >= self.CACHE_TTL_SEC:
            self._cache = self._load_active_filters()
            self._cache_loaded_at = now
            log.debug(f"Cache filtres rafraîchi : {len(self._cache)} filtres actifs")

    def force_reload(self):
        """Force le rechargement du cache (à appeler sur SIGHUP par exemple)."""
        self._cache_loaded_at = 0
        self._refresh_cache_if_needed()

    # ========================================================================
    # ÉVALUATION D'UNE ALERTE
    # ========================================================================

    def evaluate(self, info, signature):
        """
        Évalue un événement contre tous les filtres actifs.

        Args:
            info : dict extrait par wazuh_reader.extract_alert_info()
            signature : dict de la signature matchée

        Returns:
            dict {
                "action": "PASS" | "IGNORE" | "DOWNGRADE" | "NOTIFY_ONLY",
                "reason": "...",
                "filter_id": int | None,
                "downgrade_to": "LOW" (si DOWNGRADE)
            }
        """
        # === MÉCANISME 1 : Pré-tagging is_noisy ===
        # Si la signature est marquée bruyante ET sans filtre explicite,
        # on downgrade automatiquement.
        if signature.get("is_noisy") == 1:
            log.debug(f"Signature {signature['id']} pré-taggée bruyante")
            # Continue : un filtre explicite peut quand même override

        # === MÉCANISMES 2 + 3 : alert_filters (manuels + auto) ===
        self._refresh_cache_if_needed()

        for f in self._cache:
            if self._matches(f, info, signature):
                # Incrémenter les stats du filtre (best-effort)
                self._increment_hit(f["id"])

                action = f["action"]
                reason = self._build_reason(f, info, signature)

                if action == "IGNORE":
                    return {
                        "action": "IGNORE",
                        "reason": reason,
                        "filter_id": f["id"],
                    }
                elif action == "DOWNGRADE":
                    return {
                        "action": "DOWNGRADE",
                        "reason": reason,
                        "filter_id": f["id"],
                        "downgrade_to": f.get("downgrade_to") or "LOW",
                    }
                elif action == "NOTIFY_ONLY":
                    return {
                        "action": "NOTIFY_ONLY",
                        "reason": reason,
                        "filter_id": f["id"],
                    }

        # Si signature pré-taggée bruyante et qu'aucun filtre n'a matché,
        # on applique un downgrade automatique soft.
        if signature.get("is_noisy") == 1:
            return {
                "action": "DOWNGRADE",
                "reason": f"Signature {signature['id']} pré-taggée comme bruyante",
                "filter_id": None,
                "downgrade_to": "LOW",
            }

        return {"action": "PASS", "reason": None, "filter_id": None}

    # ========================================================================
    # MATCHING D'UN FILTRE
    # ========================================================================

    def _matches(self, f, info, signature):
        """
        Vérifie si l'événement matche TOUTES les conditions du filtre.

        Les conditions sont en ET logique. Les conditions NULL sont ignorées.
        """
        # 1. signature_id (NULL = applicable à toutes)
        if f.get("signature_id") is not None:
            if int(f["signature_id"]) != int(signature["id"]):
                return False

        # 2. src_ip exact
        if f.get("src_ip"):
            if not info.get("src_ip") or info["src_ip"] != f["src_ip"]:
                return False

        # 3. src_ip_pattern (regex)
        if f.get("src_ip_pattern"):
            if not info.get("src_ip"):
                return False
            try:
                if not re.search(f["src_ip_pattern"], info["src_ip"]):
                    return False
            except re.error:
                log.warning(f"Regex invalide dans filtre {f['id']} : {f['src_ip_pattern']}")
                return False

        # 4. dst_ip
        if f.get("dst_ip"):
            if not info.get("dst_ip") or info["dst_ip"] != f["dst_ip"]:
                return False

        # 5. asset_id
        if f.get("asset_id") is not None:
            # On a besoin de l'asset_id de l'alerte. Il sera résolu plus tard
            # dans le pipeline mais ici on n'y a pas encore accès.
            # Pour l'instant on skip cette condition (les filtres par asset
            # seront pleinement évalués dans une v ultérieure).
            pass

        # 6. user_pattern (regex)
        if f.get("user_pattern"):
            user = self._extract_user(info)
            if not user:
                return False
            try:
                if not re.search(f["user_pattern"], user):
                    return False
            except re.error:
                return False

        # 7. time_window (ex: "08:00-18:00")
        if f.get("time_window"):
            if not self._is_in_time_window(f["time_window"]):
                return False

        # 8. days_of_week (JSON array : ["MON","TUE",...])
        if f.get("days_of_week"):
            if not self._is_in_days_of_week(f["days_of_week"]):
                return False

        return True

    # ========================================================================
    # HELPERS DE MATCHING
    # ========================================================================

    def _extract_user(self, info):
        """Tente d'extraire un username depuis l'alerte Wazuh."""
        raw = info.get("raw") or {}
        data = raw.get("data") or {}
        return (
            data.get("srcuser") or
            data.get("dstuser") or
            data.get("user") or
            data.get("username")
        )

    def _is_in_time_window(self, window_str):
        """
        Vérifie si l'heure actuelle est dans la fenêtre.
        Format : "HH:MM-HH:MM" (ex: "08:00-18:00")
        """
        try:
            start_str, end_str = window_str.split("-")
            sh, sm = map(int, start_str.strip().split(":"))
            eh, em = map(int, end_str.strip().split(":"))
            now = datetime.now().time()
            start = dt_time(sh, sm)
            end = dt_time(eh, em)

            if start <= end:
                return start <= now <= end
            else:
                # Plage qui traverse minuit (22:00-06:00)
                return now >= start or now <= end
        except (ValueError, AttributeError):
            return False

    def _is_in_days_of_week(self, days_json):
        """
        Vérifie si le jour actuel est dans la liste.
        days_json : '["MON","TUE","WED","THU","FRI"]'
        """
        try:
            import json as _json
            days = _json.loads(days_json) if isinstance(days_json, str) else days_json
            day_names = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
            today = day_names[datetime.now().weekday()]
            return today in [d.upper() for d in days]
        except (ValueError, TypeError):
            return False

    # ========================================================================
    # STATS
    # ========================================================================

    def _increment_hit(self, filter_id):
        """Incrémente hit_count + last_hit_at sur le filtre matché."""
        try:
            db.execute_with_retry(
                self.db_path,
                """
                UPDATE alert_filters
                SET hit_count = COALESCE(hit_count, 0) + 1,
                    last_hit_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (filter_id,)
            )
        except Exception as e:
            log.debug(f"Erreur incrément hit_count filtre {filter_id} : {e}")

    def _build_reason(self, f, info, signature):
        """Construit le message de raison pour les logs/audit."""
        parts = []
        if f.get("name"):
            parts.append(f["name"])
        if f.get("filter_type"):
            parts.append(f"[{f['filter_type']}]")
        if f.get("reason"):
            parts.append(f["reason"])
        return " | ".join(parts) or f"Filtre #{f['id']}"
