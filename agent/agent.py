#!/usr/bin/env python3
"""
================================================================================
SIEM Africa — Module 3 : Agent intelligent
Point d'entrée principal
================================================================================

Cet agent :
- Lit les alertes Wazuh en temps réel depuis alerts.json
- Les corrèle avec la base de signatures (Module 2)
- Enrichit, filtre les faux positifs, déclenche des réponses actives
- Notifie par email les alertes critiques
- Lance les honeypots SSH/HTTP/MySQL
- Génère des explications IA via Ollama local

Lancement :
    python3 agent.py                    # En foreground
    sudo systemctl start siem-agent     # Via systemd (recommandé)
================================================================================
"""

import os
import sys
import time
import signal
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Ajouter le dossier parent au PYTHONPATH pour trouver le package modules/
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from modules.config import get_config
from modules import db
from modules.wazuh_reader import WazuhReader
from modules.alert_processor import AlertProcessor


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(config):
    """Configure le logging vers fichier + stdout."""
    log_file = config.get("LOG_FILE", "/var/log/siem-africa/agent.log")
    log_level = getattr(logging, config.get("LOG_LEVEL", "INFO").upper(), logging.INFO)

    # Créer le dossier de logs si besoin
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    except OSError as e:
        print(f"Erreur création dossier log : {e}", file=sys.stderr)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    root = logging.getLogger("siem-agent")
    root.setLevel(log_level)

    # Vider les handlers existants (en cas de reload)
    root.handlers = []

    # Handler fichier rotatif (10 MB × 5 fichiers)
    try:
        fh = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        fh.setFormatter(fmt)
        fh.setLevel(log_level)
        root.addHandler(fh)
    except (IOError, OSError) as e:
        print(f"Impossible d'écrire dans {log_file} : {e}", file=sys.stderr)

    # Handler stdout (capturé par systemd → journalctl)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(log_level)
    root.addHandler(sh)

    return root


# ============================================================================
# GESTION DES SIGNAUX (arrêt propre)
# ============================================================================

class GracefulShutdown:
    """Gestionnaire d'arrêt propre via SIGTERM/SIGINT."""

    def __init__(self):
        self.should_stop = False
        signal.signal(signal.SIGTERM, self._handler)
        signal.signal(signal.SIGINT, self._handler)
        # SIGHUP = recharger config (sans redémarrer)
        signal.signal(signal.SIGHUP, self._reload_handler)
        self._reload_requested = False

    def _handler(self, signum, frame):
        self.should_stop = True

    def _reload_handler(self, signum, frame):
        self._reload_requested = True

    def reload_pending(self):
        if self._reload_requested:
            self._reload_requested = False
            return True
        return False


# ============================================================================
# PID FILE
# ============================================================================

def write_pid_file(pid_path):
    """Écrit le PID actuel dans pid_path."""
    try:
        os.makedirs(os.path.dirname(pid_path), exist_ok=True)
        with open(pid_path, "w") as f:
            f.write(str(os.getpid()))
    except (IOError, OSError) as e:
        logging.getLogger("siem-agent").warning(f"Impossible d'écrire le PID : {e}")


def remove_pid_file(pid_path):
    try:
        if os.path.exists(pid_path):
            os.remove(pid_path)
    except OSError:
        pass


# ============================================================================
# BANNIÈRE DE DÉMARRAGE
# ============================================================================

def print_banner(log, config):
    log.info("=" * 70)
    log.info("  SIEM Africa — Agent intelligent (Module 3)")
    log.info("=" * 70)
    log.info(f"  PID            : {os.getpid()}")
    log.info(f"  BDD            : {config.get('DB_PATH')}")
    log.info(f"  alerts.json    : {config.get('ALERTS_JSON')}")
    log.info(f"  Polling        : {config.get_int('POLLING_INTERVAL_SEC')}s")
    log.info(f"  Active Response: {'ON' if config.get_bool('ACTIVE_RESPONSE_ENABLED') else 'OFF'}")
    log.info(f"  Honeypot       : {'ON' if config.get_bool('HONEYPOT_ENABLED') else 'OFF'}")
    log.info(f"  IA Ollama      : {'ON' if config.get_bool('AI_ENABLED') else 'OFF'}")
    log.info(f"  Langue         : {config.get('LANG')}")
    log.info("=" * 70)


# ============================================================================
# HEALTHCHECK PRÉ-DÉMARRAGE
# ============================================================================

def preflight_checks(log, config):
    """Vérifications obligatoires avant de démarrer l'agent."""
    errors = []
    warnings = []

    # 1. BDD accessible
    db_path = config.get("DB_PATH")
    health = db.healthcheck(db_path)

    if not health["exists"]:
        errors.append(f"BDD introuvable : {db_path}. Module 2 installé ?")
    elif not health["readable"]:
        errors.append(f"BDD non lisible : {db_path}")
    elif not health["tables_ok"]:
        errors.append(f"BDD incomplète (< 22 tables). Réinstaller le Module 2.")
    elif not health["fk_ok"]:
        warnings.append("Violations de foreign key détectées (PRAGMA foreign_key_check)")
    elif not health["integrity_ok"]:
        errors.append("PRAGMA integrity_check a échoué : BDD corrompue")
    elif not health["writable"]:
        errors.append(f"BDD en lecture seule. Permissions insuffisantes ? "
                      f"(L'agent doit être dans le groupe siem-africa)")
    else:
        log.info(f"✓ BDD OK : {db_path}")

    # 2. alerts.json existe (warning seulement, l'agent attendra)
    alerts_path = config.get("ALERTS_JSON")
    if not os.path.exists(alerts_path):
        warnings.append(
            f"alerts.json absent ({alerts_path}). "
            f"L'agent attendra son apparition. Wazuh est-il démarré ?"
        )

    # 3. SMTP configuré (warning seulement)
    if not config.get("SMTP_USER") or not config.get("ALERT_EMAIL"):
        warnings.append("SMTP non configuré ou ALERT_EMAIL vide. Aucun email ne sera envoyé.")

    # Affichage
    for w in warnings:
        log.warning(f"⚠ {w}")
    for e in errors:
        log.error(f"✗ {e}")

    return len(errors) == 0


# ============================================================================
# BOUCLE PRINCIPALE
# ============================================================================

def main_loop(log, config, processor, reader, shutdown,
              noise_killer=None, honeypot=None):
    """Boucle principale : lit, traite, dort, recommence."""

    polling = config.get_int("POLLING_INTERVAL_SEC", 5)
    batch_size = config.get_int("BATCH_SIZE", 100)
    iteration = 0

    # Bruit-killer : on calcule le nombre d'itérations entre chaque passe
    # (par défaut : 1h = 3600s ; à polling=5s => 720 itérations)
    nk_window_sec = 3600  # 1h fixe
    nk_iterations = max(1, nk_window_sec // polling)
    next_nk_iteration = nk_iterations  # première passe à +1h

    log.info("Boucle principale démarrée")

    while not shutdown.should_stop:
        iteration += 1

        # Recharger la config si SIGHUP reçu
        if shutdown.reload_pending():
            log.info("SIGHUP reçu — rechargement config")
            config.reload_db_settings()

        # Lire les nouvelles alertes
        try:
            alerts = reader.read_new_alerts(max_lines=batch_size)
        except Exception as e:
            log.error(f"Erreur lecture alertes : {e}")
            alerts = []

        # Traiter
        for raw_alert in alerts:
            if shutdown.should_stop:
                break
            try:
                processor.process(raw_alert)
            except Exception as e:
                log.exception(f"Erreur traitement : {e}")

        # Logging périodique des stats (toutes les 12 itérations soit ~1 min à 5s)
        if iteration % 12 == 0:
            stats = processor.get_stats()
            log.info(
                f"Stats : reçues={stats['alerts_received']} "
                f"insérées={stats['alerts_inserted']} "
                f"filtrées={stats['alerts_filtered']} "
                f"corrélées={stats['alerts_correlated']} "
                f"erreurs={stats['errors']}"
            )

        # Bruit-killer : passe toutes les nk_iterations (~1h)
        if noise_killer and iteration >= next_nk_iteration:
            try:
                log.info("Lancement passe bruit-killer (cycle horaire)")
                nk_stats = noise_killer.run()
                log.info(f"Bruit-killer : {nk_stats}")
                # Recharger le cache de filtres pour prendre en compte
                # les nouveaux filtres AUTO_NOISE
                if processor.filter_engine:
                    processor.filter_engine.force_reload()
            except Exception as e:
                log.error(f"Erreur bruit-killer : {e}")
            next_nk_iteration = iteration + nk_iterations

        # Sleep
        time.sleep(polling)

    log.info("Boucle principale arrêtée proprement")

    # Cleanup honeypot
    if honeypot:
        try:
            honeypot.stop()
        except Exception:
            pass


# ============================================================================
# MAIN
# ============================================================================

def main():
    # 1. Charger config
    config = get_config()

    # 2. Setup logging
    log = setup_logging(config)

    # 3. PID file
    pid_path = config.get("PID_FILE")
    write_pid_file(pid_path)

    # 4. Bannière
    print_banner(log, config)

    # 5. Vérifications pré-démarrage
    if not preflight_checks(log, config):
        log.error("Préflight check échoué — arrêt")
        remove_pid_file(pid_path)
        return 1

    # 6. Création des composants
    processor = AlertProcessor(config)
    reader = WazuhReader(config.get("ALERTS_JSON"))

    # 7. Attente initiale du fichier alerts.json (max 60s)
    if not reader.wait_for_file(max_wait_sec=60):
        log.warning("alerts.json toujours absent — l'agent continue mais ne traitera rien")

    # 8. Reprise depuis le dernier offset
    reader.resume_from_offset()

    # 9. Modules Lot 2 (filtres, corrélation, enrichissement)
    from modules.filters import FilterEngine
    from modules.correlator import Correlator
    from modules.enrichment import Enricher

    filter_engine = FilterEngine(config)
    correlator = Correlator(config)
    enricher = Enricher(config)

    processor.attach_filters(filter_engine)
    processor.attach_correlator(correlator)
    processor.attach_enricher(enricher)

    log.info("Modules Lot 2 branchés : FilterEngine + Correlator + Enricher")

    # 10. Modules Lot 3 (notifier, responder, ai, auditor, honeypot, noise_killer)
    from modules.notifier import Notifier
    from modules.active_response import ActiveResponder
    from modules.ai_explainer import AIExplainer
    from modules.audit import Auditor
    from modules.honeypot import Honeypot
    from modules.noise_killer import NoiseKiller

    notifier = Notifier(config)
    responder = ActiveResponder(config)
    ai = AIExplainer(config)
    auditor = Auditor(config)

    processor.attach_notifier(notifier)
    processor.attach_responder(responder)
    processor.attach_ai(ai)
    processor.attach_auditor(auditor)

    log.info("Modules Lot 3 branchés : Notifier + ActiveResponder + AI + Auditor")

    # 10a. Restaurer les blocages iptables (survie aux redémarrages)
    if config.get_bool("ACTIVE_RESPONSE_ENABLED"):
        try:
            responder.cleanup_expired_on_startup()
        except Exception as e:
            log.error(f"Erreur restauration blocages : {e}")

    # 10b. Démarrer les honeypots
    honeypot = Honeypot(config, active_responder=responder)
    if config.get_bool("HONEYPOT_ENABLED"):
        try:
            honeypot.start()
        except Exception as e:
            log.error(f"Erreur démarrage honeypots : {e}")

    # 10c. Bruit-killer : on l'instancie pour le mode embedded (run périodique)
    noise_killer = NoiseKiller(config)

    # IA healthcheck (info)
    try:
        ai_health = ai.healthcheck()
        if ai_health.get("enabled"):
            if ai_health.get("available"):
                log.info(f"✓ Ollama disponible : {ai_health.get('configured_model')} (loaded: {ai_health.get('model_loaded')})")
            else:
                log.warning(f"⚠ Ollama non disponible : {ai_health.get('error', 'unknown')}")
    except Exception:
        pass

    # 10. Gestion arrêt propre
    shutdown = GracefulShutdown()

    # 11. Boucle principale
    try:
        main_loop(log, config, processor, reader, shutdown,
                  noise_killer=noise_killer, honeypot=honeypot)
    except KeyboardInterrupt:
        log.info("Interruption clavier")
    except Exception as e:
        log.exception(f"Erreur fatale : {e}")
        remove_pid_file(pid_path)
        return 2

    # 12. Cleanup
    final_stats = processor.get_stats()
    log.info(f"Stats finales : {final_stats}")
    remove_pid_file(pid_path)
    log.info("Agent arrêté proprement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
