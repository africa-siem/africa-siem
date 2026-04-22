#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# install.sh — Script principal d'installation avec menu interactif
# ============================================================================
#
# Ce script est le POINT D'ENTRÉE PRINCIPAL pour installer le Module 1.
#
# Il affiche un menu permettant de choisir entre :
#   - Mode LITE (Wazuh Manager + Snort, 4 GB RAM)
#   - Mode FULL (all-in-one avec Dashboard, 8 GB RAM)
#
# Après le choix, il lance le script correspondant :
#   - install-lite.sh
#   - install-full.sh
#
# Pour une installation directe sans menu, utilisez plutôt :
#   sudo ./install-lite.sh
#   sudo ./install-full.sh
#
# ============================================================================

# --- Répertoire du script (pour trouver les fichiers relatifs) ------------
# BASH_SOURCE[0] = chemin de ce script
# dirname = extrait le dossier parent
# readlink -f = résout les liens symboliques
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Chargement des fonctions utilitaires --------------------------------
# On charge d'abord logging.sh pour avoir log_info, log_error, etc.
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"

# Ensuite langue.sh pour la traduction
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/langue.sh"

# ============================================================================
# FONCTION PRINCIPALE : Affichage du menu
# ============================================================================

# --- show_main_menu : Affiche le menu et lit le choix utilisateur ---------
# Retourne le mode choisi via echo : "lite" ou "full"
# Retourne "quit" si l'utilisateur veut quitter.
show_main_menu() {
    local choice

    while true; do
        clear
        log_banner "$(t welcome_title)"

        echo -e "          ${COLOR_CYAN}$(t welcome_subtitle)${COLOR_RESET}"
        echo ""
        echo ""
        echo -e "  ${COLOR_BOLD}$(t menu_title)${COLOR_RESET}"
        echo ""
        echo "  ┌─────────────────────────────────────────────┐"
        echo "  │                                             │"
        echo -e "  │  ${COLOR_GREEN}[1]${COLOR_RESET} $(t menu_lite)      │"
        echo -e "  │      ${COLOR_CYAN}$(t menu_lite_desc)${COLOR_RESET}  │"
        echo "  │                                             │"
        echo -e "  │  ${COLOR_BLUE}[2]${COLOR_RESET} $(t menu_full)       │"
        echo -e "  │      ${COLOR_CYAN}$(t menu_full_desc)${COLOR_RESET} │"
        echo "  │                                             │"
        echo -e "  │  ${COLOR_YELLOW}[3]${COLOR_RESET} $(t menu_quit)                                │"
        echo "  │                                             │"
        echo "  └─────────────────────────────────────────────┘"
        echo ""
        echo -ne "  ${COLOR_BOLD}$(t choose)${COLOR_RESET} : "
        read -r choice

        case "$choice" in
            1|lite|LITE)
                echo "lite"
                return 0
                ;;
            2|full|FULL)
                echo "full"
                return 0
                ;;
            3|q|Q|quit|exit)
                echo "quit"
                return 0
                ;;
            *)
                echo ""
                log_error "$(t invalid_choice)"
                sleep 2
                ;;
        esac
    done
}

# ============================================================================
# FONCTION : Affichage de l'écran de confirmation avant installation
# ============================================================================

# --- show_install_summary : Affiche un récap avant de lancer l'install ----
# Argument : $1 = "lite" ou "full"
show_install_summary() {
    local mode=$1

    clear
    log_banner "INSTALLATION $(echo "$mode" | tr '[:lower:]' '[:upper:]')"

    echo -e "  ${COLOR_BOLD}Récapitulatif de l'installation :${COLOR_RESET}"
    echo ""

    if [ "$mode" = "lite" ]; then
        echo -e "  📦 Mode               : ${COLOR_GREEN}LITE${COLOR_RESET} (léger)"
        echo -e "  💾 RAM requise        : 4 GB minimum"
        echo -e "  💽 Disque requis      : 50 GB minimum"
        echo -e "  🧩 Composants         :"
        echo -e "     • Snort IDS"
        echo -e "     • Wazuh Manager"
        echo -e "  ❌ Interface web Wazuh : Non (utiliser Module 4)"
    else
        echo -e "  📦 Mode               : ${COLOR_BLUE}FULL${COLOR_RESET} (complet)"
        echo -e "  💾 RAM requise        : 8 GB minimum"
        echo -e "  💽 Disque requis      : 50 GB minimum"
        echo -e "  🧩 Composants         :"
        echo -e "     • Snort IDS"
        echo -e "     • Wazuh Manager"
        echo -e "     • Wazuh Indexer"
        echo -e "     • Wazuh Dashboard"
        echo -e "  ✅ Interface web Wazuh : Oui (https://<IP>)"
    fi

    echo ""
    echo -e "  ⏱️  Durée estimée     : ~10-15 minutes"
    echo -e "  🌐 Internet requis    : Oui (téléchargement des paquets)"
    echo -e "  🔒 Privilèges         : root (sudo)"
    echo ""
    echo -e "  ${COLOR_YELLOW}⚠️  L'installation modifiera votre système.${COLOR_RESET}"
    echo -e "  ${COLOR_YELLOW}    Assurez-vous d'avoir une sauvegarde si nécessaire.${COLOR_RESET}"
    echo ""

    if ! ask_confirmation "$(t ask_confirm_install)"; then
        log_info "Installation annulée par l'utilisateur"
        return 1
    fi

    return 0
}

# ============================================================================
# MAIN : Exécution principale du script
# ============================================================================

main() {
    # Vérification basique : est-on root ?
    # (On ne peut pas appeler check_root() de prerequis.sh car on ne l'a pas chargé)
    if [ "$(id -u)" -ne 0 ]; then
        echo ""
        echo "❌ ERREUR : Ce script doit être exécuté en tant que root."
        echo ""
        echo "   Relancez avec :"
        echo "   sudo ./install.sh"
        echo ""
        exit 1
    fi

    # Initialisation du système de log
    log_init

    log_info "Démarrage de l'installation SIEM Africa Module 1"
    log_info "Script : install.sh (menu interactif)"

    # Étape 1 : sélection de la langue
    select_language

    # Étape 2 : affichage du menu principal
    local selected_mode
    selected_mode=$(show_main_menu)

    # Si l'utilisateur a choisi "quitter"
    if [ "$selected_mode" = "quit" ]; then
        log_info "Installation annulée par l'utilisateur"
        echo ""
        echo "À bientôt !"
        exit 0
    fi

    # Étape 3 : récapitulatif et confirmation
    if ! show_install_summary "$selected_mode"; then
        log_info "Installation annulée à l'étape de confirmation"
        exit 0
    fi

    # Étape 4 : appel du script d'installation correspondant
    local target_script
    if [ "$selected_mode" = "lite" ]; then
        target_script="${SCRIPT_DIR}/install-lite.sh"
    else
        target_script="${SCRIPT_DIR}/install-full.sh"
    fi

    # Vérification de l'existence du script cible
    if [ ! -f "$target_script" ]; then
        log_error "Script introuvable : ${target_script}"
        log_error "Installation corrompue. Clonez à nouveau depuis GitHub."
        exit 1
    fi

    # Vérification des permissions d'exécution
    if [ ! -x "$target_script" ]; then
        log_info "Application des permissions d'exécution..."
        chmod +x "$target_script"
    fi

    # Exécution du script choisi
    # On passe la langue sélectionnée en variable d'environnement
    log_info "Lancement de ${target_script}..."
    echo ""

    # exec remplace le processus actuel par le nouveau script
    # Comme ça, les logs et le contexte sont conservés
    SIEM_LANG="$SIEM_LANG" exec "$target_script"
}

# --- Lancement de main() --------------------------------------------------
# Le "$@" passe tous les arguments reçus (aucun pour l'instant, mais au cas où)
main "$@"
