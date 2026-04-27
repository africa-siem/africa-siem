"""
Module de configuration de l'agent SIEM Africa.

Charge la configuration depuis :
1. Fichier .env (/etc/siem-africa/agent.env)
2. Table settings de la BDD (override pour les paramètres dynamiques)
3. Variables d'environnement (override final)
"""

import os
import logging
from pathlib import Path

log = logging.getLogger("siem-agent.config")


# ============================================================================
# CHEMINS PAR DÉFAUT (cohérents avec Module 1 et Module 2)
# ============================================================================

DEFAULTS = {
    # Chemins système
    "DB_PATH": "/var/lib/siem-africa/siem.db",
    "ALERTS_JSON": "/var/ossec/logs/alerts/alerts.json",
    "LOG_FILE": "/var/log/siem-africa/agent.log",
    "PID_FILE": "/var/run/siem-africa-agent.pid",
    "ENV_FILE": "/etc/siem-africa/agent.env",

    # Comportement de l'agent
    "POLLING_INTERVAL_SEC": "5",
    "BATCH_SIZE": "100",
    "LOG_LEVEL": "INFO",

    # Corrélation
    "CORRELATION_WINDOW_SEC": "60",
    "CORRELATION_THRESHOLD": "3",

    # Active Response
    "ACTIVE_RESPONSE_ENABLED": "1",
    "ACTIVE_RESPONSE_DELAY_SEC": "300",
    "ACTIVE_RESPONSE_DURATION_SEC": "3600",

    # Honeypot
    "HONEYPOT_ENABLED": "1",
    "HONEYPOT_SSH_PORT": "2222",
    "HONEYPOT_HTTP_PORT": "8888",
    "HONEYPOT_MYSQL_PORT": "3307",
    "HONEYPOT_AUTO_BLOCK_DURATION_SEC": "3600",

    # IA Ollama
    "AI_ENABLED": "1",
    "AI_PROVIDER": "ollama",
    "AI_OLLAMA_URL": "http://localhost:11434",
    "AI_OLLAMA_MODEL": "llama3.2:3b",
    "AI_TIMEOUT_SEC": "30",
    "AI_CACHE_ENABLED": "1",

    # Bruit-killer
    "NOISE_KILLER_THRESHOLD": "100",
    "NOISE_KILLER_WINDOW_HOURS": "1",
    "NOISE_KILLER_FILTER_DURATION_HOURS": "24",

    # SMTP (à configurer obligatoirement)
    "SMTP_HOST": "localhost",
    "SMTP_PORT": "25",
    "SMTP_USER": "",
    "SMTP_PASSWORD": "",
    "SMTP_USE_TLS": "1",
    "SMTP_FROM": "siem-africa@localhost",

    # Notifications
    "ALERT_EMAIL": "",
    "EMAIL_DEDUP_WINDOW_MIN": "15",
    "MIN_SEVERITY_FOR_EMAIL": "HIGH",
    "LANG": "fr",

    # Serveur
    "SERVER_IP": "127.0.0.1",
    "DASHBOARD_URL": "http://127.0.0.1:8000",
}


# ============================================================================
# PARSING .ENV
# ============================================================================

def parse_env_file(path):
    """Parse un fichier .env (KEY=VALUE), retourne un dict."""
    if not os.path.exists(path):
        log.warning(f"Fichier .env introuvable : {path}")
        return {}

    config = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    log.warning(f"Ligne {lineno} ignorée (pas de =) : {line}")
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                # Retirer les quotes éventuelles
                if (v.startswith('"') and v.endswith('"')) or \
                   (v.startswith("'") and v.endswith("'")):
                    v = v[1:-1]
                config[k] = v
    except Exception as e:
        log.error(f"Erreur lecture {path} : {e}")
        return {}

    return config


# ============================================================================
# OVERRIDE DEPUIS BDD (table settings)
# ============================================================================

# Liste des settings BDD qui peuvent override le .env
DB_OVERRIDABLE_KEYS = [
    "AI_ENABLED",
    "AI_OLLAMA_MODEL",
    "ALERT_EMAIL",
    "MIN_SEVERITY_FOR_EMAIL",
    "LANG",
    "EMAIL_DEDUP_WINDOW_MIN",
    "ACTIVE_RESPONSE_ENABLED",
    "HONEYPOT_ENABLED",
    "NOISE_KILLER_THRESHOLD",
    "NOISE_KILLER_WINDOW_HOURS",
]

# Mapping clé .env → clé BDD
DB_KEY_MAPPING = {
    "AI_ENABLED": "ai.enabled",
    "AI_OLLAMA_MODEL": "ai.model",
    "ALERT_EMAIL": "smtp.alert_email",
    "MIN_SEVERITY_FOR_EMAIL": "notifications.min_severity_email",
    "LANG": "system.language",
    "EMAIL_DEDUP_WINDOW_MIN": "smtp.dedup_window_min",
    "ACTIVE_RESPONSE_ENABLED": "active_response.enabled",
    "HONEYPOT_ENABLED": "honeypot.enabled",
    "NOISE_KILLER_THRESHOLD": "detection.noise_killer_threshold",
    "NOISE_KILLER_WINDOW_HOURS": "detection.noise_killer_window_hours",
}


def load_settings_from_db(db_path, current_config):
    """
    Charge les settings depuis la table 'settings' de la BDD.
    Override certains paramètres du .env si présents.
    """
    import sqlite3

    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        for env_key in DB_OVERRIDABLE_KEYS:
            db_key = DB_KEY_MAPPING.get(env_key)
            if not db_key:
                continue
            cur.execute(
                "SELECT value FROM settings WHERE key = ? AND deleted_at IS NULL",
                (db_key,)
            )
            row = cur.fetchone()
            if row and row["value"] is not None and row["value"] != "":
                current_config[env_key] = row["value"]

        conn.close()
    except Exception as e:
        log.warning(f"Impossible de charger settings depuis BDD : {e}")

    return current_config


# ============================================================================
# CHARGEMENT PRINCIPAL
# ============================================================================

class Config:
    """
    Configuration de l'agent.

    Hiérarchie de priorité (du plus prioritaire au moins) :
    1. Variable d'environnement
    2. Settings BDD (pour les clés overridables)
    3. Fichier .env
    4. Valeurs par défaut
    """

    def __init__(self, env_file=None):
        self._config = dict(DEFAULTS)

        # 1. Charger .env
        env_path = env_file or self._config["ENV_FILE"]
        env_values = parse_env_file(env_path)
        self._config.update(env_values)
        log.info(f"Configuration chargée depuis : {env_path}")

        # 2. Charger settings BDD (si BDD accessible)
        db_path = self._config.get("DB_PATH")
        if db_path and os.path.exists(db_path):
            self._config = load_settings_from_db(db_path, self._config)

        # 3. Override par variables d'environnement
        for key in self._config.keys():
            if key in os.environ:
                self._config[key] = os.environ[key]

    def get(self, key, default=None):
        """Récupère une valeur (str)."""
        return self._config.get(key, default)

    def get_int(self, key, default=0):
        """Récupère une valeur en int."""
        try:
            return int(self._config.get(key, default))
        except (ValueError, TypeError):
            return default

    def get_bool(self, key, default=False):
        """Récupère une valeur booléenne."""
        v = str(self._config.get(key, "")).strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off", ""):
            return False
        return default

    def get_path(self, key, default=None):
        """Récupère un chemin (Path)."""
        v = self._config.get(key, default)
        return Path(v) if v else None

    def reload_db_settings(self):
        """Recharge les settings depuis la BDD (utile pour les changements à chaud)."""
        db_path = self._config.get("DB_PATH")
        if db_path and os.path.exists(db_path):
            self._config = load_settings_from_db(db_path, self._config)
            log.debug("Settings BDD rechargés")

    def __repr__(self):
        # Masquer les secrets dans l'affichage
        safe = {}
        for k, v in self._config.items():
            if any(s in k.upper() for s in ("PASSWORD", "SECRET", "TOKEN", "KEY")):
                safe[k] = "***" if v else ""
            else:
                safe[k] = v
        return f"Config({safe})"


# ============================================================================
# SINGLETON GLOBAL
# ============================================================================

_instance = None


def get_config():
    """Retourne l'instance singleton de Config."""
    global _instance
    if _instance is None:
        _instance = Config()
    return _instance


def reload_config():
    """Force le rechargement complet de la config."""
    global _instance
    _instance = None
    return get_config()
