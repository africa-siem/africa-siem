"""
Module d'enrichissement contextuel des alertes.

Ajoute du contexte aux alertes brutes pour faciliter l'investigation :
    - Score de réputation IP (table ip_reputation)
    - Géolocalisation IP (pays, ASN) — via cache local
    - Mapping MITRE ATT&CK (déjà résolu via JOIN dans signature)
    - Threat intel (IoCs connus)
    - Stats locales : nb alertes 24h pour cette IP
"""

import logging
import ipaddress
from datetime import datetime

from modules import db

log = logging.getLogger("siem-agent.enrichment")


class Enricher:
    """
    Enrichisseur d'alertes.

    Toutes les opérations sont best-effort : si une donnée n'est pas
    disponible, l'enrichissement continue avec ce qui est disponible.
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")

    # ========================================================================
    # POINT D'ENTRÉE PRINCIPAL
    # ========================================================================

    def enrich(self, info, signature, asset):
        """
        Enrichit une alerte avec le contexte disponible.

        Args:
            info : dict extrait par wazuh_reader
            signature : dict signature matchée (avec MITRE déjà résolu)
            asset : dict asset associé (peut être None)

        Returns:
            dict d'enrichissement (à insérer dans alerts.enriched_data en JSON)
        """
        enriched = {
            "enriched_at": datetime.now().isoformat(),
        }

        # === IP source : réputation + géoloc ===
        if info.get("src_ip"):
            src_ctx = self._enrich_ip(info["src_ip"], role="source")
            if src_ctx:
                enriched["src_ip_context"] = src_ctx

        # === IP destination : réputation seulement ===
        if info.get("dst_ip"):
            dst_ctx = self._enrich_ip(info["dst_ip"], role="destination")
            if dst_ctx:
                enriched["dst_ip_context"] = dst_ctx

        # === MITRE ATT&CK (déjà résolu via JOIN dans signature) ===
        mitre_ctx = self._build_mitre_context(signature)
        if mitre_ctx:
            enriched["mitre"] = mitre_ctx

        # === Asset context ===
        if asset:
            enriched["asset_context"] = {
                "id": asset.get("id"),
                "hostname": asset.get("hostname"),
                "criticality": asset.get("criticality"),
                "environment": asset.get("environment"),
                "auto_created": asset.get("auto_created", False),
            }

        # === Threat intel (IoCs connus) ===
        ioc_match = self._check_threat_intel(info)
        if ioc_match:
            enriched["threat_intel"] = ioc_match

        # === Stats locales ===
        if info.get("src_ip"):
            stats = self._compute_local_stats(info["src_ip"], signature["id"])
            if stats:
                enriched["local_stats"] = stats

        return enriched

    # ========================================================================
    # ENRICHISSEMENT IP
    # ========================================================================

    def _enrich_ip(self, ip, role="source"):
        """
        Enrichit une IP avec ip_reputation + détection IP privée.

        Returns:
            dict | None
        """
        if not self._is_valid_ip(ip):
            return None

        ctx = {"ip": ip, "is_private": False, "is_loopback": False}

        # Détection IP privée/loopback (pas besoin de la BDD)
        try:
            ipo = ipaddress.ip_address(ip)
            ctx["is_private"] = ipo.is_private
            ctx["is_loopback"] = ipo.is_loopback
        except ValueError:
            return None

        # Si IP loopback ou privée, on saute la réputation externe
        if ctx["is_private"] or ctx["is_loopback"]:
            ctx["risk_level"] = "INTERNAL"
            return ctx

        # Lookup ip_reputation
        rep = self._get_ip_reputation(ip)
        if rep:
            ctx["reputation_score"] = rep.get("reputation_score")
            ctx["risk_level"] = rep.get("risk_level")
            ctx["country_code"] = rep.get("country_code")
            ctx["asn_name"] = rep.get("asn_name")
            ctx["alert_count_total"] = rep.get("alert_count")

            # Mettre à jour le compteur d'alertes pour cette IP
            self._increment_ip_alert_count(ip)
        else:
            ctx["risk_level"] = "UNKNOWN"
            # Créer une entrée vide pour suivre cette IP
            self._create_ip_reputation_stub(ip)

        return ctx

    def _is_valid_ip(self, ip):
        if not ip:
            return False
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False

    def _get_ip_reputation(self, ip):
        """Lookup dans ip_reputation."""
        sql = "SELECT * FROM ip_reputation WHERE ip_address = ? LIMIT 1"
        try:
            row = db.execute_with_retry(self.db_path, sql, (ip,), fetch_one=True)
            return dict(row) if row else None
        except Exception as e:
            log.debug(f"Erreur lookup reputation {ip} : {e}")
            return None

    def _create_ip_reputation_stub(self, ip):
        """Crée une entrée minimale pour suivre une IP nouvelle."""
        sql = """
            INSERT OR IGNORE INTO ip_reputation
                (ip_address, reputation_score, risk_level, alert_count, first_seen)
            VALUES (?, 50, 'UNKNOWN', 1, CURRENT_TIMESTAMP)
        """
        try:
            db.execute_with_retry(self.db_path, sql, (ip,))
        except Exception as e:
            log.debug(f"Erreur création stub IP {ip} : {e}")

    def _increment_ip_alert_count(self, ip):
        """Incrémente le compteur d'alertes pour une IP."""
        sql = """
            UPDATE ip_reputation
            SET alert_count = COALESCE(alert_count, 0) + 1,
                last_seen_alert = CURRENT_TIMESTAMP
            WHERE ip_address = ?
        """
        try:
            db.execute_with_retry(self.db_path, sql, (ip,))
        except Exception as e:
            log.debug(f"Erreur incrément alert_count IP {ip} : {e}")

    # ========================================================================
    # MITRE ATT&CK
    # ========================================================================

    def _build_mitre_context(self, signature):
        """
        Construit le contexte MITRE depuis la signature (déjà JOINée).

        Returns: dict | None
        """
        if not signature.get("mitre_technique_id"):
            return None

        return {
            "technique_id": signature.get("mitre_technique_id"),
            "technique_name": signature.get("mitre_technique_name"),
            "tactic_id": signature.get("mitre_tactic_id"),
            "tactic_name": signature.get("mitre_tactic_name"),
            "url": f"https://attack.mitre.org/techniques/{signature.get('mitre_technique_id', '')}/",
        }

    # ========================================================================
    # THREAT INTEL
    # ========================================================================

    def _check_threat_intel(self, info):
        """
        Vérifie si une des IPs/valeurs est un IoC connu.

        Returns: dict | None
        """
        candidates = []

        if info.get("src_ip"):
            candidates.append(("ip", info["src_ip"]))
        if info.get("dst_ip"):
            candidates.append(("ip", info["dst_ip"]))

        # Domaine extractible du raw ?
        raw = info.get("raw") or {}
        data = raw.get("data") or {}
        if data.get("hostname"):
            candidates.append(("domain", data["hostname"]))

        if not candidates:
            return None

        for ioc_type, value in candidates:
            row = self._lookup_ioc(ioc_type, value)
            if row:
                return {
                    "ioc_type": ioc_type,
                    "value": value,
                    "source": row.get("source"),
                    "confidence": row.get("confidence"),
                    "severity": row.get("severity"),
                    "description": row.get("description_fr") or row.get("description"),
                }
        return None

    def _lookup_ioc(self, ioc_type, value):
        """Lookup un IoC dans threat_intel."""
        sql = """
            SELECT * FROM threat_intel
            WHERE ioc_type = ? AND value = ?
              AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ORDER BY confidence DESC
            LIMIT 1
        """
        try:
            row = db.execute_with_retry(
                self.db_path, sql, (ioc_type, value), fetch_one=True
            )
            return dict(row) if row else None
        except Exception as e:
            log.debug(f"Erreur lookup IoC {ioc_type}={value} : {e}")
            return None

    # ========================================================================
    # STATS LOCALES
    # ========================================================================

    def _compute_local_stats(self, src_ip, signature_id):
        """
        Calcule des statistiques locales utiles pour l'investigation.

        Returns:
            dict avec :
                - alerts_24h_for_ip : nombre d'alertes en 24h pour cette IP
                - alerts_24h_for_signature : nombre d'alertes 24h pour la sig
                - is_recurrent_attacker : True si IP a > 10 alertes en 24h
                - has_been_blocked : True si IP a déjà été blockée
                - has_false_positives : True si IP a déjà été marquée FP
        """
        stats = {}

        # Alertes 24h pour cette IP
        try:
            row = db.execute_with_retry(
                self.db_path,
                """
                SELECT COUNT(*) AS nb FROM alerts
                WHERE src_ip = ?
                  AND created_at >= datetime('now', '-24 hours')
                """,
                (src_ip,),
                fetch_one=True
            )
            stats["alerts_24h_for_ip"] = row["nb"] if row else 0
            stats["is_recurrent_attacker"] = stats["alerts_24h_for_ip"] > 10
        except Exception:
            pass

        # Alertes 24h pour la signature
        try:
            row = db.execute_with_retry(
                self.db_path,
                """
                SELECT COUNT(*) AS nb FROM alerts
                WHERE signature_id = ?
                  AND created_at >= datetime('now', '-24 hours')
                """,
                (signature_id,),
                fetch_one=True
            )
            stats["alerts_24h_for_signature"] = row["nb"] if row else 0
        except Exception:
            pass

        # Cette IP a-t-elle déjà été blockée ?
        try:
            row = db.execute_with_retry(
                self.db_path,
                "SELECT COUNT(*) AS nb FROM blocked_ips WHERE ip_address = ?",
                (src_ip,),
                fetch_one=True
            )
            stats["has_been_blocked"] = (row["nb"] if row else 0) > 0
        except Exception:
            pass

        # Cette IP a-t-elle déjà eu des alertes marquées FALSE_POSITIVE ?
        try:
            row = db.execute_with_retry(
                self.db_path,
                """
                SELECT COUNT(*) AS nb FROM alerts
                WHERE src_ip = ? AND status = 'FALSE_POSITIVE'
                """,
                (src_ip,),
                fetch_one=True
            )
            stats["has_false_positives"] = (row["nb"] if row else 0) > 0
        except Exception:
            pass

        return stats
