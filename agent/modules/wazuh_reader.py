"""
Module de lecture des alertes Wazuh depuis alerts.json.

Particularités importantes (issues du retour d'expérience SIEM Africa) :
- Les endpoints API Wazuh /alerts et /security/events n'existent pas dans 4.7.5+
- La méthode officielle et fiable est de tailer alerts.json
- Gère la rotation du fichier (logrotate) via détection de truncation
- Gère le redémarrage de Wazuh (recréation du fichier)
- Persistance de la position de lecture (offset) entre redémarrages
"""

import os
import json
import time
import logging
from pathlib import Path

log = logging.getLogger("siem-agent.wazuh_reader")


# Fichier où on persiste la position de lecture (offset)
OFFSET_FILE = "/var/lib/siem-africa/agent_offset.txt"


class WazuhReader:
    """
    Lecteur incrémental de /var/ossec/logs/alerts/alerts.json.

    Usage :
        reader = WazuhReader("/var/ossec/logs/alerts/alerts.json")
        reader.start_from_end()  # ou reader.resume_from_offset()

        while True:
            alerts = reader.read_new_alerts(max_lines=100)
            for alert in alerts:
                process(alert)
            time.sleep(5)
    """

    def __init__(self, alerts_path, offset_file=None):
        self.alerts_path = str(alerts_path)
        self.offset_file = offset_file or OFFSET_FILE
        self.position = 0
        self._inode = None  # détecter rotation logrotate

    # ========================================================================
    # POSITIONNEMENT INITIAL
    # ========================================================================

    def start_from_end(self):
        """
        Positionne le lecteur à la FIN du fichier actuel.
        À utiliser au premier démarrage : ignore l'historique, ne traite que
        les nouvelles alertes.
        """
        if os.path.exists(self.alerts_path):
            self.position = os.path.getsize(self.alerts_path)
            self._inode = os.stat(self.alerts_path).st_ino
            log.info(f"Position initiale : fin du fichier ({self.position} octets)")
        else:
            self.position = 0
            log.info(f"alerts.json n'existe pas encore : {self.alerts_path}")
        self._save_offset()

    def start_from_beginning(self):
        """
        Positionne le lecteur au DÉBUT du fichier.
        À utiliser pour rejouer l'historique complet.
        """
        self.position = 0
        if os.path.exists(self.alerts_path):
            self._inode = os.stat(self.alerts_path).st_ino
        log.info("Position initiale : début du fichier")
        self._save_offset()

    def resume_from_offset(self):
        """
        Reprend depuis la dernière position connue (lecture du fichier offset).
        Si aucun offset trouvé, démarre depuis la fin.
        """
        if os.path.exists(self.offset_file):
            try:
                with open(self.offset_file, "r") as f:
                    data = f.read().strip()
                    parts = data.split(":")
                    self.position = int(parts[0])
                    self._inode = int(parts[1]) if len(parts) > 1 else None
                log.info(f"Reprise depuis offset : position={self.position} inode={self._inode}")
                # Vérifier que l'inode correspond toujours
                if os.path.exists(self.alerts_path):
                    current_inode = os.stat(self.alerts_path).st_ino
                    if self._inode and self._inode != current_inode:
                        log.warning("Inode différent — fichier remplacé. Démarrage depuis la fin.")
                        self.start_from_end()
                        return
                    # Vérifier que la position est valide
                    file_size = os.path.getsize(self.alerts_path)
                    if self.position > file_size:
                        log.warning(f"Offset {self.position} > taille {file_size} — démarrage depuis la fin")
                        self.start_from_end()
                        return
            except (ValueError, IOError) as e:
                log.warning(f"Impossible de lire l'offset ({e}) — démarrage depuis la fin")
                self.start_from_end()
        else:
            log.info("Aucun offset persisté — démarrage depuis la fin")
            self.start_from_end()

    # ========================================================================
    # PERSISTANCE OFFSET
    # ========================================================================

    def _save_offset(self):
        """Sauvegarde la position actuelle dans le fichier offset."""
        try:
            os.makedirs(os.path.dirname(self.offset_file), exist_ok=True)
            with open(self.offset_file, "w") as f:
                f.write(f"{self.position}:{self._inode or 0}")
        except IOError as e:
            log.error(f"Erreur sauvegarde offset : {e}")

    # ========================================================================
    # DÉTECTION DE ROTATION / TRUNCATION
    # ========================================================================

    def _check_rotation(self):
        """
        Détecte si le fichier a été tronqué (logrotate) ou recréé (redémarrage Wazuh).
        Retourne True si une rotation a été détectée et la position a été reset.
        """
        if not os.path.exists(self.alerts_path):
            log.warning(f"alerts.json disparu : {self.alerts_path}")
            return False

        try:
            stat = os.stat(self.alerts_path)
        except OSError:
            return False

        # Cas 1 : fichier remplacé (inode différent → logrotate)
        if self._inode is not None and stat.st_ino != self._inode:
            log.info(f"Rotation détectée (inode {self._inode} → {stat.st_ino}) — reset position")
            self.position = 0
            self._inode = stat.st_ino
            self._save_offset()
            return True

        # Cas 2 : fichier tronqué (taille plus petite que position)
        if stat.st_size < self.position:
            log.info(f"Truncation détectée (taille {stat.st_size} < position {self.position}) — reset")
            self.position = 0
            self._save_offset()
            return True

        # Cas 3 : premier accès, on enregistre l'inode
        if self._inode is None:
            self._inode = stat.st_ino

        return False

    # ========================================================================
    # LECTURE DES ALERTES
    # ========================================================================

    def read_new_alerts(self, max_lines=100):
        """
        Lit les nouvelles lignes depuis la dernière position.

        Args:
            max_lines : nombre max d'alertes lues par appel (anti-flood)

        Returns:
            list de dicts (alertes Wazuh parsées)
        """
        if not os.path.exists(self.alerts_path):
            return []

        # Vérifier rotation/truncation
        self._check_rotation()

        alerts = []
        try:
            with open(self.alerts_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self.position)
                lines_read = 0

                for line in f:
                    if lines_read >= max_lines:
                        # Ne pas mettre à jour la position complètement,
                        # le reste sera lu au prochain appel
                        self.position = f.tell()
                        break

                    line = line.strip()
                    if not line:
                        continue

                    try:
                        alert = json.loads(line)
                        alerts.append(alert)
                        lines_read += 1
                    except json.JSONDecodeError as e:
                        # Ligne tronquée (Wazuh écrit en cours) — on s'arrête là
                        # et on retentera au prochain cycle
                        log.debug(f"Ligne JSON incomplète, attente du flush Wazuh : {e}")
                        break
                else:
                    # Tout lu jusqu'à EOF
                    self.position = f.tell()

            self._save_offset()

        except IOError as e:
            log.error(f"Erreur lecture {self.alerts_path} : {e}")

        return alerts

    # ========================================================================
    # ATTENTE DU FICHIER
    # ========================================================================

    def wait_for_file(self, max_wait_sec=60, check_interval=5):
        """
        Attend que alerts.json existe (utile au démarrage si Wazuh est lent).

        Returns: True si le fichier est apparu, False sinon.
        """
        elapsed = 0
        while elapsed < max_wait_sec:
            if os.path.exists(self.alerts_path):
                log.info(f"alerts.json disponible après {elapsed}s")
                return True
            log.info(f"Attente de {self.alerts_path}... ({elapsed}/{max_wait_sec}s)")
            time.sleep(check_interval)
            elapsed += check_interval
        log.warning(f"alerts.json toujours absent après {max_wait_sec}s")
        return False


# ============================================================================
# EXTRACTION DES INFOS UTILES D'UNE ALERTE WAZUH
# ============================================================================

def extract_alert_info(wazuh_alert):
    """
    Extrait les champs métier d'une alerte Wazuh brute.

    Format Wazuh standard (alerts.json) :
    {
        "timestamp": "...",
        "rule": { "id": "5712", "level": 10, "description": "...", ... },
        "agent": { "id": "001", "name": "...", "ip": "..." },
        "data": { "srcip": "...", "dstip": "...", ... },
        "decoder": {...},
        "location": "..."
    }

    Returns: dict normalisé
    """
    rule = wazuh_alert.get("rule", {}) or {}
    agent = wazuh_alert.get("agent", {}) or {}
    data = wazuh_alert.get("data", {}) or {}

    # IPs : Wazuh stocke parfois dans data, parfois à la racine
    src_ip = (
        data.get("srcip") or
        data.get("src_ip") or
        wazuh_alert.get("srcip") or
        wazuh_alert.get("src_ip")
    )
    dst_ip = (
        data.get("dstip") or
        data.get("dst_ip") or
        wazuh_alert.get("dstip")
    )

    # Conversion ports en int (Wazuh les met parfois en string)
    def _to_int(v):
        if v is None:
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None

    # rule_id en int (signatures.id est INTEGER)
    rule_id = _to_int(rule.get("id"))

    # Détection si c'est du Snort relayé par Wazuh
    # Snort dans Wazuh : rule_id ~86xxx et data.id contient le SID Snort
    source_system = "WAZUH"
    sid_snort = None
    rule_groups = rule.get("groups", []) or []
    if "snort" in [g.lower() for g in rule_groups]:
        source_system = "SNORT"
        sid_snort = _to_int(data.get("id"))
        if sid_snort:
            rule_id = sid_snort  # On utilise le SID Snort comme signature.id

    return {
        "timestamp": wazuh_alert.get("timestamp"),
        "source_system": source_system,
        "rule_id": rule_id,
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule_groups,
        "src_ip": src_ip,
        "src_port": _to_int(data.get("src_port") or data.get("srcport")),
        "dst_ip": dst_ip,
        "dst_port": _to_int(data.get("dst_port") or data.get("dstport")),
        "protocol": data.get("protocol"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "decoder": (wazuh_alert.get("decoder") or {}).get("name"),
        "location": wazuh_alert.get("location"),
        "raw": wazuh_alert,
    }


def map_wazuh_level_to_severity(level):
    """
    Convertit un niveau Wazuh (0-15) en sévérité SIEM Africa.

    Wazuh levels (officiels) :
        0   : ignored
        1-3 : low / informational
        4-6 : warning / medium
        7-11: high
        12-14: critical
        15  : severe (rare)
    """
    try:
        level = int(level)
    except (ValueError, TypeError):
        return "MEDIUM"

    if level >= 12:
        return "CRITICAL"
    elif level >= 7:
        return "HIGH"
    elif level >= 4:
        return "MEDIUM"
    elif level >= 1:
        return "LOW"
    else:
        return "INFO"
