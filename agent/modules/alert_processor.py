"""
Module de traitement principal des alertes.

Orchestre le pipeline complet :
    1. Réception alerte Wazuh brute
    2. Extraction des champs
    3. Insertion raw_event (audit)
    4. Lookup signature dans la BDD
    5. Application des filtres FP (mécanismes 1, 2, 3)
    6. Corrélation (déduplication intelligente)
    7. Enrichissement (asset, IP rep, MITRE, géoloc)
    8. Création de l'alerte enrichie
    9. Active Response (si CRITICAL)
    10. Génération explication IA (si activé)
    11. Notifications (email + dashboard)
    12. Audit log

Note : ce fichier orchestre, il appelle d'autres modules pour les détails.
       Les modules filters.py, correlator.py, etc. seront livrés au Lot 2.
"""

import uuid
import json
import logging
from datetime import datetime

from modules import db
from modules import wazuh_reader

log = logging.getLogger("siem-agent.processor")


class AlertProcessor:
    """
    Orchestrateur principal du traitement des alertes.

    Note : tant que les modules filters/correlator/enrichment/notifier/etc.
    ne sont pas livrés (Lots 2-3), ce processeur fonctionne en mode "minimal" :
    il insère raw_events + alerts + audit_log, mais sans filtrage avancé,
    sans IA, sans honeypot, sans active response, sans email.

    Une fois les autres modules livrés, ils seront branchés ici.
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")

        # Stats runtime
        self.stats = {
            "alerts_received": 0,
            "alerts_filtered": 0,
            "alerts_correlated": 0,
            "alerts_inserted": 0,
            "errors": 0,
            "started_at": datetime.now().isoformat(),
        }

        # Cache anti-doublons court terme (déduplique les alertes Wazuh
        # qui arrivent plusieurs fois en quelques secondes)
        self._recent_keys = {}  # key → timestamp
        self._dedup_window_sec = 10

        # Modules optionnels (branchés au Lot 2-3)
        self.filter_engine = None
        self.correlator = None
        self.enricher = None
        self.notifier = None
        self.responder = None
        self.ai = None
        self.auditor = None

    # ========================================================================
    # API D'ATTACHEMENT (utilisée par agent.py au démarrage)
    # ========================================================================

    def attach_filters(self, filter_engine):
        """Attache le moteur de filtres FP (Lot 2)."""
        self.filter_engine = filter_engine

    def attach_correlator(self, correlator):
        """Attache le corrélateur (Lot 2)."""
        self.correlator = correlator

    def attach_enricher(self, enricher):
        """Attache l'enrichisseur (Lot 2)."""
        self.enricher = enricher

    def attach_notifier(self, notifier):
        """Attache le notifieur (Lot 3)."""
        self.notifier = notifier

    def attach_responder(self, responder):
        """Attache l'active response (Lot 3)."""
        self.responder = responder

    def attach_ai(self, ai):
        """Attache l'IA (Lot 3)."""
        self.ai = ai

    def attach_auditor(self, auditor):
        """Attache le module d'audit (Lot 3)."""
        self.auditor = auditor

    # ========================================================================
    # POINT D'ENTRÉE PRINCIPAL
    # ========================================================================

    def process(self, wazuh_alert):
        """
        Traite une alerte Wazuh brute.

        Pipeline complet :
            extract → raw_event → dedup → signature → filter → correlate →
            enrich → insert alert → respond → ai → notify → audit

        Args:
            wazuh_alert : dict brut tel que parsé depuis alerts.json

        Returns:
            int | None : id de l'alerte insérée, ou None si filtré/dupliqué
        """
        self.stats["alerts_received"] += 1

        try:
            return self._process_internal(wazuh_alert)
        except Exception as e:
            self.stats["errors"] += 1
            log.exception(f"Erreur traitement alerte : {e}")
            return None

    def _process_internal(self, wazuh_alert):
        """Pipeline interne (séparé pour gestion d'erreur globale)."""

        # === PHASE 1 : EXTRACTION ===
        info = wazuh_reader.extract_alert_info(wazuh_alert)

        if not info["rule_id"]:
            log.debug("Alerte sans rule_id ignorée")
            return None

        # === PHASE 2 : DÉDUPLICATION COURT-TERME ===
        # Évite de retraiter la même alerte Wazuh qui aurait été lue 2 fois
        # (ex: rotation de fichier mal détectée)
        dedup_key = self._make_dedup_key(info)
        if self._is_recent_duplicate(dedup_key):
            log.debug(f"Alerte récemment vue, ignorée : {dedup_key}")
            return None
        self._mark_recent(dedup_key)

        # === PHASE 3 : INSERTION raw_event (audit du brut) ===
        raw_event_id = self._insert_raw_event(info)

        # === PHASE 4 : LOOKUP SIGNATURE ===
        signature = db.lookup_signature(
            self.db_path,
            info["rule_id"],
            source=info["source_system"]
        )

        if not signature:
            log.info(
                f"Signature inconnue : rule_id={info['rule_id']} "
                f"({info['source_system']}) — {info['rule_description']}"
            )
            # On enregistre quand même comme raw_event pour analyse offline.
            # Dans une v2, on pourrait insérer dans une table 'unknown_signatures'.
            return None

        # === PHASE 5 : FILTRES FAUX POSITIFS (Lot 2) ===
        if self.filter_engine:
            filter_decision = self.filter_engine.evaluate(info, signature)
            if filter_decision["action"] == "IGNORE":
                self.stats["alerts_filtered"] += 1
                log.info(f"Alerte filtrée : {filter_decision['reason']}")
                return None
            elif filter_decision["action"] == "DOWNGRADE":
                signature = dict(signature)  # copy pour ne pas muter
                signature["severity"] = filter_decision.get("downgrade_to", "LOW")
        else:
            # Lot 1 : filtre minimal sur is_active
            if signature.get("is_active") == 0:
                log.debug(f"Signature désactivée : {signature['id']}")
                return None

        # === PHASE 6 : CORRÉLATION (Lot 2) ===
        if self.correlator:
            existing_alert_id = self.correlator.find_existing(info, signature)
            if existing_alert_id:
                self.correlator.merge_into(existing_alert_id, info)
                self.stats["alerts_correlated"] += 1
                log.debug(f"Alerte mergée dans #{existing_alert_id}")
                return existing_alert_id

        # === PHASE 7 : ENRICHISSEMENT (Lot 2) ===
        enriched_data = {}
        asset = None

        if info["src_ip"]:
            asset = db.find_or_create_asset(
                self.db_path,
                info["src_ip"],
                hostname=info.get("agent_name")
            )

        if self.enricher:
            enriched_data = self.enricher.enrich(info, signature, asset)

        # === PHASE 8 : INSERTION ALERTE ===
        alert_id = self._insert_alert(info, signature, asset, enriched_data)
        if not alert_id:
            return None

        self.stats["alerts_inserted"] += 1
        log.info(
            f"Alerte #{alert_id} créée : [{signature['severity']}] "
            f"{signature['name']} depuis {info['src_ip']}"
        )

        # === PHASE 9 : ACTIVE RESPONSE (Lot 3) ===
        if self.responder and signature["severity"] == "CRITICAL":
            try:
                self.responder.handle(alert_id, info, signature)
            except Exception as e:
                log.error(f"Erreur Active Response : {e}")

        # === PHASE 10 : IA EXPLICATION (Lot 3) ===
        if self.ai:
            try:
                self.ai.explain_async(alert_id, signature, enriched_data)
            except Exception as e:
                log.error(f"Erreur IA : {e}")

        # === PHASE 11 : NOTIFICATIONS (Lot 3) ===
        if self.notifier:
            try:
                self.notifier.notify(alert_id, signature, info, enriched_data)
            except Exception as e:
                log.error(f"Erreur notification : {e}")

        # === PHASE 12 : AUDIT LOG (Lot 3) ===
        if self.auditor:
            try:
                self.auditor.log_alert_created(alert_id, signature, info)
            except Exception as e:
                log.error(f"Erreur audit : {e}")

        return alert_id

    # ========================================================================
    # HELPERS INTERNES
    # ========================================================================

    def _make_dedup_key(self, info):
        """Génère une clé de déduplication court terme."""
        return f"{info['rule_id']}|{info['src_ip']}|{info['dst_ip']}|{info['dst_port']}"

    def _is_recent_duplicate(self, key):
        """Vérifie si la clé a été vue il y a < dedup_window_sec secondes."""
        import time
        now = time.time()
        # Nettoyage périodique des vieilles entrées
        if len(self._recent_keys) > 1000:
            cutoff = now - self._dedup_window_sec
            self._recent_keys = {
                k: v for k, v in self._recent_keys.items() if v > cutoff
            }
        last = self._recent_keys.get(key, 0)
        return (now - last) < self._dedup_window_sec

    def _mark_recent(self, key):
        import time
        self._recent_keys[key] = time.time()

    def _insert_raw_event(self, info):
        """Insère l'événement brut dans raw_events."""
        try:
            event_data = {
                "event_uuid": str(uuid.uuid4()),
                "source_system": info["source_system"],
                "source_rule_id": info["rule_id"],
                "event_timestamp": info["timestamp"],
                "src_ip": info["src_ip"],
                "src_port": info["src_port"],
                "dst_ip": info["dst_ip"],
                "dst_port": info["dst_port"],
                "protocol": info["protocol"],
                "message": info["rule_description"],
                "raw_payload": json.dumps(info["raw"], ensure_ascii=False)[:10000],
                "asset_id": None,  # résolu plus tard
            }
            return db.insert_raw_event(self.db_path, event_data)
        except Exception as e:
            log.error(f"Erreur insertion raw_event : {e}")
            return None

    def _insert_alert(self, info, signature, asset, enriched_data):
        """Insère l'alerte enrichie dans alerts."""
        try:
            now = datetime.now().isoformat()
            title = f"{signature['name']} depuis {info['src_ip'] or 'inconnu'}"

            alert_data = {
                "alert_uuid": str(uuid.uuid4()),
                "signature_id": signature["id"],
                "severity": signature["severity"],
                "confidence": signature.get("confidence", 75),
                "title": title[:500],
                "description": signature.get("description_fr") or signature.get("description"),
                "src_ip": info["src_ip"],
                "dst_ip": info["dst_ip"],
                "asset_id": asset["id"] if asset else None,
                "event_count": 1,
                "first_seen": info["timestamp"] or now,
                "last_seen": info["timestamp"] or now,
                "status": "NEW",
                "enriched_data": json.dumps(enriched_data, ensure_ascii=False) if enriched_data else None,
            }
            return db.insert_alert(self.db_path, alert_data)
        except Exception as e:
            log.error(f"Erreur insertion alerte : {e}")
            return None

    # ========================================================================
    # STATS
    # ========================================================================

    def get_stats(self):
        """Retourne les statistiques runtime."""
        return dict(self.stats)
