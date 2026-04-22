#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# core/logging.sh — Fonctions de logging uniformes
# ============================================================================
#
# Ce fichier fournit les fonctions de log utilisées par tous les scripts
# d'installation. Il garantit un affichage cohérent (couleurs, symboles)
# et un fichier de log centralisé dans /var/log/siem-africa/install.log
#
# Utilisation :
#   source core/logging.sh
#   log_info "Message d'information"
#   log_success "Opération réussie"
#   log_warning "Attention"
#   log_error "Erreur critique"
#
# ============================================================================

# --- Couleurs ANSI ----------------------------------------------------------
# On utilise des couleurs pour faciliter la lecture dans le terminal.
# NO_COLOR désactive les couleurs (pour les logs fichier).
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_BOLD='\033[1m'
readonly COLOR_RESET='\033[0m'

# --- Configuration du fichier de log ----------------------------------------
# Le log d'installation est centralisé à cet emplacement.
# Il est créé à la première utilisation de log_init().
readonly LOG_DIR="/var/log/siem-africa"
readonly LOG_FILE="${LOG_DIR}/install.log"

# --- Initialisation du système de log --------------------------------------
# Cette fonction doit être appelée UNE FOIS au début du script principal.
# Elle crée le dossier de log si nécessaire et initialise le fichier.
log_init() {
    # Si on n'est pas root, on ne peut pas créer /var/log/siem-africa
    # Dans ce cas on log dans /tmp (fallback)
    if [ "$(id -u)" -ne 0 ]; then
        LOG_FILE="/tmp/siem-africa-install.log"
    else
        mkdir -p "$LOG_DIR" 2>/dev/null
        chmod 755 "$LOG_DIR" 2>/dev/null
    fi

    # Écrire une en-tête dans le fichier de log
    {
        echo ""
        echo "============================================================"
        echo "SIEM AFRICA - Log d'installation"
        echo "Démarré le : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Utilisateur : $(whoami)"
        echo "Hostname : $(hostname)"
        echo "============================================================"
        echo ""
    } >> "$LOG_FILE" 2>/dev/null
}

# --- Fonction interne : écrire dans le fichier de log ----------------------
# Les messages sont horodatés pour faciliter le debug.
_log_to_file() {
    local level=$1
    local message=$2
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE" 2>/dev/null
}

# --- log_info : Message d'information -------------------------------------
# Usage : log_info "Démarrage de l'installation"
log_info() {
    local message=$1
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET}    ${message}"
    _log_to_file "INFO" "$message"
}

# --- log_success : Opération réussie (vert) ------------------------------
# Usage : log_success "Installation de Snort terminée"
log_success() {
    local message=$1
    echo -e "${COLOR_GREEN}[✓]${COLOR_RESET}       ${message}"
    _log_to_file "SUCCESS" "$message"
}

# --- log_warning : Avertissement (jaune) ---------------------------------
# Usage : log_warning "RAM limite, performances dégradées"
log_warning() {
    local message=$1
    echo -e "${COLOR_YELLOW}[⚠ WARN]${COLOR_RESET}  ${message}"
    _log_to_file "WARNING" "$message"
}

# --- log_error : Erreur critique (rouge) ---------------------------------
# Usage : log_error "Impossible de se connecter à internet"
log_error() {
    local message=$1
    echo -e "${COLOR_RED}[✗ ERROR]${COLOR_RESET} ${message}" >&2
    _log_to_file "ERROR" "$message"
}

# --- log_step : Début d'une étape (titre) --------------------------------
# Usage : log_step "3/8" "Vérification des prérequis"
log_step() {
    local step_num=$1
    local step_title=$2
    echo ""
    echo -e "${COLOR_CYAN}${COLOR_BOLD}[ÉTAPE ${step_num}] ${step_title}${COLOR_RESET}"
    echo -e "${COLOR_CYAN}────────────────────────────────────────────────────${COLOR_RESET}"
    _log_to_file "STEP" "=== ÉTAPE ${step_num} : ${step_title} ==="
}

# --- log_banner : Affiche une bannière visuelle --------------------------
# Usage : log_banner "SIEM AFRICA - INSTALLATION"
log_banner() {
    local title=$1
    local line
    line=$(printf '═%.0s' {1..60})

    echo ""
    echo -e "${COLOR_CYAN}╔${line}╗${COLOR_RESET}"
    printf "${COLOR_CYAN}║${COLOR_RESET}${COLOR_BOLD}  %-56s  ${COLOR_RESET}${COLOR_CYAN}║${COLOR_RESET}\n" "$title"
    echo -e "${COLOR_CYAN}╚${line}╝${COLOR_RESET}"
    echo ""

    _log_to_file "BANNER" "$title"
}

# --- log_separator : Ligne de séparation ---------------------------------
log_separator() {
    echo ""
    echo -e "${COLOR_CYAN}────────────────────────────────────────────────────${COLOR_RESET}"
    echo ""
}

# --- die : Arrêt brutal avec message d'erreur ----------------------------
# Usage : die "Impossible de continuer : raison X"
# Cette fonction log l'erreur et quitte avec code 1.
die() {
    local message=$1
    log_error "$message"
    log_error "Installation interrompue. Consultez ${LOG_FILE} pour plus de détails."
    exit 1
}

# --- ask_confirmation : Demande confirmation O/N --------------------------
# Usage : if ask_confirmation "Voulez-vous continuer ?"; then ... fi
# Retourne 0 si OUI, 1 si NON.
ask_confirmation() {
    local question=$1
    local response

    while true; do
        echo -ne "${COLOR_YELLOW}[?]${COLOR_RESET} ${question} [O/n] "
        read -r response
        case "$response" in
            [OoYy]|[OoYy][Uu][Ii]|"")
                return 0
                ;;
            [Nn]|[Nn][Oo][Nn])
                return 1
                ;;
            *)
                echo "Répondez par O (oui) ou N (non)."
                ;;
        esac
    done
}

# --- show_progress : Affiche une barre de progression simple --------------
# Usage : show_progress 3 8 "Installation Snort"
show_progress() {
    local current=$1
    local total=$2
    local label=$3
    local percent=$(( current * 100 / total ))
    local filled=$(( percent / 5 ))
    local empty=$(( 20 - filled ))

    printf "\r${COLOR_CYAN}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "] ${percent}%% ${label}${COLOR_RESET}"

    if [ "$current" -eq "$total" ]; then
        echo ""
    fi
}

# ============================================================================
# Fin de core/logging.sh
# ============================================================================
