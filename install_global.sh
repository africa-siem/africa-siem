#!/usr/bin/env bash
#
# SIEM Africa - global installer (Modules 1 + 2 + 3 in one shot)
# Target : Ubuntu 22.04 LTS (root required)
#
# RULE #16: no environment variable is exported toward the sub-scripts.
# Each sub-script is invoked exactly the way the user would invoke it,
# with a real terminal (/dev/tty) so it can prompt for its own inputs.

LC_ALL=C
LANG=C

RAW_BASE="https://raw.githubusercontent.com/africa-siem/africa-siem/main"
LANG_CHOICE=""
VARIANT=""
TMP_DIR=""
INSTALL_SMTP="n"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
[ -z "$SCRIPT_DIR" ] && SCRIPT_DIR=""

# --------- If piped from curl, attach to real terminal so `read` works ---------
if [ ! -t 0 ]; then
    if [ -r /dev/tty ]; then
        exec </dev/tty
    fi
fi

cleanup() {
    [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# --------- i18n ---------
say() {
    case "$1" in
        banner)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "=== SIEM Africa - Installation globale (Modules 1 + 2 + 3) ===" \
                || echo "=== SIEM Africa - Global install (Modules 1 + 2 + 3) ===" ;;
        variant_q)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Variante du Module 1 :" \
                || echo "Module 1 variant:" ;;
        variant_min)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "  1) Minimal  - Snort + Wazuh Manager  (~1 GB RAM)" \
                || echo "  1) Minimal  - Snort + Wazuh Manager  (~1 GB RAM)" ;;
        variant_all)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "  2) All-in-One - + Wazuh Indexer + Dashboard  (4 GB RAM recommandes)" \
                || echo "  2) All-in-One - + Wazuh Indexer + Dashboard  (4 GB RAM recommended)" ;;
        variant_choice)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Choix [1] : " \
                || echo -n "Choice [1]: " ;;
        smtp_q)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Configurer SMTP pour les emails d'alerte apres installation ? [o/N] : " \
                || echo -n "Configure SMTP for alert emails after install? [y/N]: " ;;
        running)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "--> Lancement de : $2" \
                || echo "--> Running: $2" ;;
        step_ok)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "OK   : $2" \
                || echo "OK   : $2" ;;
        step_fail)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "ECHEC: $2" \
                || echo "FAIL : $2" ;;
        continue_q)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo -n "Continuer malgre l'echec ? [o/N] : " \
                || echo -n "Continue despite the failure? [y/N]: " ;;
        abort)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation globale interrompue." \
                || echo "Global install aborted." ;;
        success)
            [ "$LANG_CHOICE" = "fr" ] \
                && echo "Installation globale terminee." \
                || echo "Global install complete." ;;
    esac
}

# --------- 0. Pre-flight ---------
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must run as root. Use: sudo bash $0"
    exit 1
fi
if ! grep -q "Ubuntu 22.04" /etc/os-release 2>/dev/null; then
    echo "WARNING: this script is tested on Ubuntu 22.04 LTS only."
    echo -n "Continue anyway? [y/N]: "
    read -r cont
    case "$cont" in
        y|Y|o|O) : ;;
        *) exit 1 ;;
    esac
fi

# --------- 1. Language ---------
echo "================================================"
echo " SIEM Africa - Global Installer"
echo "================================================"
echo ""
echo "Language / Langue :"
echo "  1) Francais"
echo "  2) English"
echo -n "Choice [1]: "
read -r lang_input
case "${lang_input:-1}" in
    2) LANG_CHOICE="en" ;;
    *) LANG_CHOICE="fr" ;;
esac
echo ""
say banner
echo ""

# --------- 2. Ask variant & SMTP preference (asked ONCE here, not exported) ---------
say variant_q
say variant_min
say variant_all
say variant_choice
read -r variant_in
case "${variant_in:-1}" in
    2) VARIANT="all"     ;;
    *) VARIANT="minimal" ;;
esac
echo ""
say smtp_q
read -r smtp_in
case "$smtp_in" in
    y|Y|o|O) INSTALL_SMTP="y" ;;
    *)       INSTALL_SMTP="n" ;;
esac
echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "Chaque sous-module va maintenant se lancer et vous poser ses propres"
    echo "questions (langue, organisation, email...). C'est normal."
else
    echo "Each sub-module will now run and ask its own questions"
    echo "(language, organization, email...). This is expected."
fi
echo ""

# --------- 3. Resolve sub-script paths: local first, otherwise curl ---------
resolve() {
    # $1 : relative path inside the repo   (e.g. installation/install.sh)
    # echoes the absolute path of the script to execute (local or downloaded).
    local rel="$1"
    if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/${rel}" ]; then
        echo "${SCRIPT_DIR}/${rel}"
        return
    fi
    if [ -z "$TMP_DIR" ]; then
        TMP_DIR=$(mktemp -d /tmp/siem-africa-global.XXXXXX)
    fi
    local target="${TMP_DIR}/${rel}"
    mkdir -p "$(dirname "$target")"
    if curl -fsSL "${RAW_BASE}/${rel}" -o "$target" 2>/dev/null && [ -s "$target" ]; then
        chmod +x "$target"
        echo "$target"
    else
        echo ""
    fi
}

run_step() {
    # $1 : relative script path; $2 : human label
    local script_path label
    script_path="$(resolve "$1")"
    label="$2"
    if [ -z "$script_path" ]; then
        say step_fail "$label (script unavailable)"
        return 1
    fi
    say running "$label"
    # Rule #16: no env export — invoke with a real terminal for its own prompts.
    bash "$script_path" </dev/tty
    local rc=$?
    if [ $rc -eq 0 ]; then
        say step_ok "$label"
        return 0
    fi
    say step_fail "$label (exit=$rc)"
    say continue_q
    read -r cont </dev/tty
    case "$cont" in
        y|Y|o|O) return 0 ;;
        *)       say abort; return 1 ;;
    esac
}

# --------- 4. Module 1 ---------
if [ "$VARIANT" = "all" ]; then
    run_step "installation/installall.sh" "Module 1 All-in-One" || exit 1
else
    run_step "installation/install.sh"    "Module 1 Minimal"   || exit 1
fi

# --------- 5. Module 2 ---------
run_step "database/install.sh" "Module 2 Database" || exit 1

# --------- 6. Module 3 ---------
run_step "agent/install.sh" "Module 3 Agent" || exit 1

# --------- 7. Optional SMTP ---------
if [ "$INSTALL_SMTP" = "y" ]; then
    run_step "agent/install-smtp.sh" "Module 3 SMTP" || true
fi

# --------- 8. Final summary ---------
echo ""
echo "================================================"
say success
echo "================================================"
echo ""
systemctl is-active snort-africa     >/dev/null 2>&1 && echo "  snort-africa        : active"    || echo "  snort-africa        : INACTIVE"
systemctl is-active wazuh-manager    >/dev/null 2>&1 && echo "  wazuh-manager       : active"    || echo "  wazuh-manager       : INACTIVE"
if [ "$VARIANT" = "all" ]; then
    systemctl is-active wazuh-indexer   >/dev/null 2>&1 && echo "  wazuh-indexer       : active"    || echo "  wazuh-indexer       : INACTIVE"
    systemctl is-active wazuh-dashboard >/dev/null 2>&1 && echo "  wazuh-dashboard     : active"    || echo "  wazuh-dashboard     : INACTIVE"
fi
systemctl is-active siem-africa-agent >/dev/null 2>&1 && echo "  siem-africa-agent  : active"    || echo "  siem-africa-agent  : INACTIVE"

echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "Credentials      : /opt/siem-africa/credentials.txt"
    echo "Logs agent       : /var/log/siem-africa/agent.log"
    echo "Base de donnees  : /opt/siem-africa/siem_africa.db"
    echo "Honeypots        : SSH:2222  HTTP:8888  MySQL:3307"
    echo ""
    echo "Le Module 4 (dashboard Django) n'est pas encore inclus."
else
    echo "Credentials      : /opt/siem-africa/credentials.txt"
    echo "Agent logs       : /var/log/siem-africa/agent.log"
    echo "Database         : /opt/siem-africa/siem_africa.db"
    echo "Honeypots        : SSH:2222  HTTP:8888  MySQL:3307"
    echo ""
    echo "Module 4 (Django dashboard) is not bundled yet."
fi

exit 0
