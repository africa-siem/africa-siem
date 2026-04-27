#!/usr/bin/env bash
# ============================================================================
# SIEM Africa — Module 3 — Vérification post-installation
# ============================================================================
# Vérifie que l'agent est correctement installé et fonctionnel.
# À lancer après ./install_agent.sh
# ============================================================================

LC_ALL=C
LANG=C

# Constantes (alignées avec install_agent.sh)
SYSTEM_GROUP="siem-africa"
SYSTEM_USER="siem-agent"
INSTALL_DIR="/opt/siem-africa-agent"
CONFIG_DIR="/etc/siem-africa"
ENV_FILE="${CONFIG_DIR}/agent.env"
DB_PATH="/var/lib/siem-africa/siem.db"
LOG_DIR="/var/log/siem-africa"
SERVICE_NAME="siem-agent"

# Couleurs
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_RESET='\033[0m'

PASS=0
WARN=0
FAIL=0

check() {
    local label="$1"
    local actual="$2"
    local expected="$3"
    local op="${4:-eq}"

    case "$op" in
        eq)
            if [ "$actual" = "$expected" ]; then
                echo -e "  ${C_GREEN}✓${C_RESET} $label : $actual"
                PASS=$((PASS+1))
            else
                echo -e "  ${C_RED}✗${C_RESET} $label : $actual ${C_RED}(attendu : $expected)${C_RESET}"
                FAIL=$((FAIL+1))
            fi
            ;;
        ge)
            if [ "$actual" -ge "$expected" ] 2>/dev/null; then
                echo -e "  ${C_GREEN}✓${C_RESET} $label : $actual"
                PASS=$((PASS+1))
            else
                echo -e "  ${C_RED}✗${C_RESET} $label : $actual ${C_RED}(attendu >= $expected)${C_RESET}"
                FAIL=$((FAIL+1))
            fi
            ;;
        contains)
            if echo "$actual" | grep -q "$expected"; then
                echo -e "  ${C_GREEN}✓${C_RESET} $label"
                PASS=$((PASS+1))
            else
                echo -e "  ${C_RED}✗${C_RESET} $label ${C_RED}(attendu contient : $expected)${C_RESET}"
                FAIL=$((FAIL+1))
            fi
            ;;
    esac
}

ok() {
    echo -e "  ${C_GREEN}✓${C_RESET} $1"
    PASS=$((PASS+1))
}

warn() {
    echo -e "  ${C_YELLOW}⚠${C_RESET} $1"
    WARN=$((WARN+1))
}

fail() {
    echo -e "  ${C_RED}✗${C_RESET} $1"
    FAIL=$((FAIL+1))
}

section() {
    echo ""
    echo -e "${C_CYAN}── $1 ──${C_RESET}"
}

# ============================================================================
# DEMARRAGE
# ============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être lancé en root (besoin de lire la BDD et /etc/siem-africa)"
    echo "Utilisez : sudo bash $0"
    exit 1
fi

clear || true
echo ""
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}              SIEM AFRICA — Module 3 (Agent) — Vérification           ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"

# ============================================================================
# CHECKS
# ============================================================================

section "Installation"

if [ -d "$INSTALL_DIR" ]; then
    ok "Dossier installation : $INSTALL_DIR"
else
    fail "Dossier installation manquant : $INSTALL_DIR"
fi

if [ -f "$INSTALL_DIR/agent.py" ]; then
    ok "agent.py présent"
else
    fail "agent.py manquant"
fi

NB_MODULES=$(ls "$INSTALL_DIR/modules/"*.py 2>/dev/null | wc -l)
check "Modules Python" "$NB_MODULES" "12" ge

if [ -f "$ENV_FILE" ]; then
    ok "Fichier configuration : $ENV_FILE"
else
    fail "Fichier configuration manquant : $ENV_FILE"
fi

# ============================================================================
section "Utilisateur système"

if id "$SYSTEM_USER" >/dev/null 2>&1; then
    ok "Utilisateur $SYSTEM_USER existe"

    if id -nG "$SYSTEM_USER" | grep -qw "$SYSTEM_GROUP"; then
        ok "Membre du groupe $SYSTEM_GROUP"
    else
        fail "Pas membre de $SYSTEM_GROUP"
    fi

    # ossec group : pour lire alerts.json
    if id -nG "$SYSTEM_USER" | grep -qw "ossec"; then
        ok "Membre du groupe ossec (lecture alerts.json)"
    else
        warn "Pas dans le groupe ossec (alerts.json peut-être non lisible)"
    fi
else
    fail "Utilisateur $SYSTEM_USER manquant"
fi

# ============================================================================
section "Permissions"

if [ -f "$ENV_FILE" ]; then
    PERMS=$(stat -c "%a" "$ENV_FILE")
    check "Permissions agent.env" "$PERMS" "640"
fi

if [ -d "$INSTALL_DIR" ]; then
    OWNER=$(stat -c "%U" "$INSTALL_DIR")
    GROUP=$(stat -c "%G" "$INSTALL_DIR")
    check "Propriétaire $INSTALL_DIR" "$OWNER" "$SYSTEM_USER"
    check "Groupe $INSTALL_DIR" "$GROUP" "$SYSTEM_GROUP"
fi

# Permissions BDD
if [ -f "$DB_PATH" ]; then
    DB_GROUP=$(stat -c "%G" "$DB_PATH")
    check "Groupe BDD" "$DB_GROUP" "$SYSTEM_GROUP"

    # Tester accès lecture par siem-agent
    if sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "SELECT 1" >/dev/null 2>&1; then
        ok "Accès BDD OK pour $SYSTEM_USER"
    else
        fail "$SYSTEM_USER ne peut pas lire la BDD"
    fi
fi

# ============================================================================
section "Service systemd"

if systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
    ok "Service systemd installé"

    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        ok "Service activé au démarrage"
    else
        warn "Service non activé (sudo systemctl enable $SERVICE_NAME)"
    fi

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        ok "Service actuellement actif"

        # Uptime du service
        UPTIME=$(systemctl show "$SERVICE_NAME" -p ActiveEnterTimestamp --value | head -1)
        if [ -n "$UPTIME" ]; then
            ok "Démarré depuis : $UPTIME"
        fi
    else
        fail "Service NON actif (systemctl status $SERVICE_NAME)"
    fi
else
    fail "Service systemd non installé"
fi

# ============================================================================
section "Connectivité aux dépendances"

# Wazuh alerts.json
ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"
if [ -f "$ALERTS_JSON" ]; then
    ok "alerts.json existe"
    if sudo -u "$SYSTEM_USER" test -r "$ALERTS_JSON"; then
        ok "alerts.json lisible par $SYSTEM_USER"
    else
        fail "alerts.json non lisible par $SYSTEM_USER"
    fi
else
    warn "alerts.json absent (Wazuh pas encore démarré ?)"
fi

# Ollama
AI_ENABLED=$(grep -E "^AI_ENABLED=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2)
if [ "$AI_ENABLED" = "1" ]; then
    OLLAMA_URL=$(grep -E "^AI_OLLAMA_URL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2)
    OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"

    if curl -s -m 5 "${OLLAMA_URL}/api/tags" >/dev/null 2>&1; then
        ok "Ollama API accessible : $OLLAMA_URL"

        OLLAMA_MODEL=$(grep -E "^AI_OLLAMA_MODEL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2)
        OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2:3b}"
        if curl -s -m 5 "${OLLAMA_URL}/api/tags" | grep -q "$OLLAMA_MODEL" 2>/dev/null; then
            ok "Modèle $OLLAMA_MODEL chargé"
        else
            warn "Modèle $OLLAMA_MODEL non chargé (ollama pull $OLLAMA_MODEL)"
        fi
    else
        warn "Ollama non joignable sur $OLLAMA_URL"
    fi
else
    ok "IA désactivée (AI_ENABLED=0)"
fi

# ============================================================================
section "Honeypots"

HONEYPOT_ENABLED=$(grep -E "^HONEYPOT_ENABLED=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2)
if [ "$HONEYPOT_ENABLED" = "1" ]; then
    for port in 2222 8888 3307; do
        if ss -tln 2>/dev/null | grep -q ":${port} "; then
            ok "Honeypot port $port à l'écoute"
        else
            # ss peut ne pas être installé ; fallback sur netstat
            if netstat -tln 2>/dev/null | grep -q ":${port} "; then
                ok "Honeypot port $port à l'écoute"
            else
                warn "Port $port non en écoute (service vient de démarrer ?)"
            fi
        fi
    done
else
    ok "Honeypots désactivés"
fi

# ============================================================================
section "Activité de l'agent"

if [ -f "$DB_PATH" ]; then
    # Compter les raw_events insérés
    NB_RAW=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM raw_events" 2>/dev/null || echo "0")
    NB_ALERTS=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts" 2>/dev/null || echo "0")
    NB_AUDIT=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM audit_log WHERE user_email='siem-agent@system'" 2>/dev/null || echo "0")
    NB_NOTIF=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM notifications" 2>/dev/null || echo "0")

    echo -e "  ${C_BLUE}ℹ${C_RESET} raw_events : $NB_RAW"
    echo -e "  ${C_BLUE}ℹ${C_RESET} alerts : $NB_ALERTS"
    echo -e "  ${C_BLUE}ℹ${C_RESET} audit_log (agent) : $NB_AUDIT"
    echo -e "  ${C_BLUE}ℹ${C_RESET} notifications : $NB_NOTIF"
fi

# Logs récents
LOG_FILE="${LOG_DIR}/agent.log"
if [ -f "$LOG_FILE" ]; then
    SIZE=$(stat -c "%s" "$LOG_FILE")
    if [ "$SIZE" -gt 0 ]; then
        ok "Logs présents : $LOG_FILE ($(du -h "$LOG_FILE" | cut -f1))"

        # Dernières erreurs
        NB_ERRORS=$(grep -c "\[ERROR\]" "$LOG_FILE" 2>/dev/null || echo "0")
        if [ "$NB_ERRORS" -gt 0 ]; then
            warn "$NB_ERRORS erreurs dans les logs (tail -30 $LOG_FILE)"
        fi
    else
        warn "Fichier log vide (l'agent vient de démarrer ?)"
    fi
else
    warn "Fichier log absent : $LOG_FILE"
fi

# ============================================================================
section "Configuration"

ALERT_EMAIL=$(grep -E "^ALERT_EMAIL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2)
if [ -n "$ALERT_EMAIL" ]; then
    ok "ALERT_EMAIL configuré : $ALERT_EMAIL"
else
    warn "ALERT_EMAIL vide (aucun email ne sera envoyé)"
fi

SMTP_HOST=$(grep -E "^SMTP_HOST=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2)
if [ -n "$SMTP_HOST" ] && [ "$SMTP_HOST" != "localhost" ]; then
    ok "SMTP configuré : $SMTP_HOST"
else
    warn "SMTP non configuré (sudo ./configure_smtp.sh)"
fi

# ============================================================================
# RESUME
# ============================================================================

echo ""
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "${C_CYAN}                          RÉSUMÉ${C_RESET}"
echo -e "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo -e "  ${C_GREEN}✓ Réussis  : $PASS${C_RESET}"
echo -e "  ${C_YELLOW}⚠ Avertis  : $WARN${C_RESET}"
echo -e "  ${C_RED}✗ Échoués  : $FAIL${C_RESET}"
echo -e "  ────────────"
TOTAL=$((PASS+WARN+FAIL))
echo -e "  Total      : $TOTAL"

if [ $FAIL -eq 0 ]; then
    echo ""
    echo -e "${C_GREEN}✓ Module 3 opérationnel${C_RESET}"
    echo ""
    echo "  Logs temps réel  : sudo journalctl -u $SERVICE_NAME -f"
    echo "  Statut détaillé  : sudo systemctl status $SERVICE_NAME"
    exit 0
else
    echo ""
    echo -e "${C_RED}⚠ Des problèmes ont été détectés${C_RESET}"
    echo "  Consulter les logs : sudo journalctl -u $SERVICE_NAME -n 50"
    exit 1
fi
