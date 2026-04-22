#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# core/langue.sh — Gestion de la langue FR/EN
# ============================================================================
#
# Ce fichier gère la sélection de langue au démarrage de l'installation.
# Il définit une variable globale SIEM_LANG ("fr" ou "en") et fournit une
# fonction t() (pour "translate") qui retourne le texte traduit.
#
# Utilisation :
#   source core/langue.sh
#   select_language
#   echo "$(t welcome_title)"
#
# ============================================================================

# --- Variable globale de langue -------------------------------------------
# Valeur par défaut : français (peut être écrasée par select_language)
SIEM_LANG="${SIEM_LANG:-fr}"

# --- Dictionnaire de traductions ------------------------------------------
# Toutes les chaînes traduisibles sont regroupées ici.
# Format : t_<lang>_<key>="Texte traduit"
#
# Pour ajouter une nouvelle chaîne :
#   1. Ajouter t_fr_ma_cle="Mon texte en français"
#   2. Ajouter t_en_ma_cle="My text in English"
#   3. Appeler : $(t ma_cle)

# ============================================================================
# FRANÇAIS
# ============================================================================
t_fr_welcome_title="BIENVENUE DANS SIEM AFRICA"
t_fr_welcome_subtitle="Solution SIEM open source pour PME africaines"
t_fr_select_language="Sélection de la langue / Language selection"
t_fr_choose="Votre choix"

# Menu principal
t_fr_menu_title="INSTALLATION — CHOISISSEZ VOTRE MODE"
t_fr_menu_lite="MODE LITE (léger - 4 GB RAM)"
t_fr_menu_lite_desc="Wazuh Manager + Snort IDS (sans interface web Wazuh)"
t_fr_menu_full="MODE FULL (complet - 8 GB RAM)"
t_fr_menu_full_desc="Wazuh Manager + Indexer + Dashboard + Snort IDS"
t_fr_menu_quit="Quitter"
t_fr_invalid_choice="Choix invalide. Veuillez réessayer."

# Étapes d'installation
t_fr_step_os="Détection du système d'exploitation"
t_fr_step_lang="Sélection de la langue"
t_fr_step_prereq="Vérification des prérequis"
t_fr_step_sysprep="Préparation du système"
t_fr_step_snort="Installation de Snort IDS"
t_fr_step_wazuh_mgr="Installation de Wazuh Manager"
t_fr_step_wazuh_indexer="Installation de Wazuh Indexer"
t_fr_step_wazuh_dash="Installation de Wazuh Dashboard"
t_fr_step_integration="Intégration Snort ↔ Wazuh"
t_fr_step_state="Génération du fichier d'état"
t_fr_step_tests="Tests de validation"

# Prérequis
t_fr_check_root="Droits root (sudo)"
t_fr_check_os="Système d'exploitation supporté"
t_fr_check_internet="Connexion internet"
t_fr_check_ram="Mémoire RAM disponible"
t_fr_check_disk="Espace disque disponible"
t_fr_check_network="Interface réseau détectée"
t_fr_check_ports="Ports réseau disponibles"
t_fr_check_corrupt="Aucune installation corrompue"

# Messages de statut
t_fr_ok="OK"
t_fr_fail="ÉCHEC"
t_fr_running="En cours"
t_fr_done="Terminé"

# Erreurs
t_fr_err_not_root="Ce script doit être exécuté en tant que root (utilisez sudo)"
t_fr_err_no_internet="Pas de connexion internet. Vérifiez votre réseau."
t_fr_err_os_not_supported="Système d'exploitation non supporté"
t_fr_err_ram_insufficient="RAM insuffisante"
t_fr_err_disk_insufficient="Espace disque insuffisant"
t_fr_err_no_interface="Aucune interface réseau active détectée"
t_fr_err_port_busy="Port déjà utilisé"

# Fin d'installation
t_fr_install_success="INSTALLATION TERMINÉE AVEC SUCCÈS"
t_fr_install_failed="INSTALLATION ÉCHOUÉE"
t_fr_see_logs="Consultez les logs pour plus de détails"
t_fr_next_step="Prochaine étape"
t_fr_credentials="Identifiants importants"
t_fr_change_password="⚠️  Changez ces mots de passe à la première connexion"

# Interactif
t_fr_ask_continue="Voulez-vous continuer ?"
t_fr_ask_confirm_install="Confirmer l'installation ?"
t_fr_ask_uninstall="Voulez-vous VRAIMENT désinstaller SIEM Africa ?"
t_fr_yes_no="[O/n]"

# ============================================================================
# ENGLISH
# ============================================================================
t_en_welcome_title="WELCOME TO SIEM AFRICA"
t_en_welcome_subtitle="Open source SIEM solution for African SMEs"
t_en_select_language="Language selection / Sélection de la langue"
t_en_choose="Your choice"

# Main menu
t_en_menu_title="INSTALLATION — CHOOSE YOUR MODE"
t_en_menu_lite="LITE MODE (lightweight - 4 GB RAM)"
t_en_menu_lite_desc="Wazuh Manager + Snort IDS (no Wazuh web interface)"
t_en_menu_full="FULL MODE (complete - 8 GB RAM)"
t_en_menu_full_desc="Wazuh Manager + Indexer + Dashboard + Snort IDS"
t_en_menu_quit="Quit"
t_en_invalid_choice="Invalid choice. Please try again."

# Installation steps
t_en_step_os="Operating system detection"
t_en_step_lang="Language selection"
t_en_step_prereq="Prerequisites check"
t_en_step_sysprep="System preparation"
t_en_step_snort="Snort IDS installation"
t_en_step_wazuh_mgr="Wazuh Manager installation"
t_en_step_wazuh_indexer="Wazuh Indexer installation"
t_en_step_wazuh_dash="Wazuh Dashboard installation"
t_en_step_integration="Snort ↔ Wazuh integration"
t_en_step_state="State file generation"
t_en_step_tests="Validation tests"

# Prerequisites
t_en_check_root="Root privileges (sudo)"
t_en_check_os="Supported operating system"
t_en_check_internet="Internet connection"
t_en_check_ram="Available RAM"
t_en_check_disk="Available disk space"
t_en_check_network="Network interface detected"
t_en_check_ports="Available network ports"
t_en_check_corrupt="No corrupted installation"

# Status messages
t_en_ok="OK"
t_en_fail="FAILED"
t_en_running="Running"
t_en_done="Done"

# Errors
t_en_err_not_root="This script must be run as root (use sudo)"
t_en_err_no_internet="No internet connection. Please check your network."
t_en_err_os_not_supported="Operating system not supported"
t_en_err_ram_insufficient="Insufficient RAM"
t_en_err_disk_insufficient="Insufficient disk space"
t_en_err_no_interface="No active network interface detected"
t_en_err_port_busy="Port already in use"

# End of installation
t_en_install_success="INSTALLATION COMPLETED SUCCESSFULLY"
t_en_install_failed="INSTALLATION FAILED"
t_en_see_logs="See logs for more details"
t_en_next_step="Next step"
t_en_credentials="Important credentials"
t_en_change_password="⚠️  Change these passwords at first login"

# Interactive
t_en_ask_continue="Do you want to continue?"
t_en_ask_confirm_install="Confirm installation?"
t_en_ask_uninstall="Do you REALLY want to uninstall SIEM Africa?"
t_en_yes_no="[Y/n]"

# ============================================================================
# FONCTION DE TRADUCTION
# ============================================================================

# --- t : Retourne la traduction d'une clé dans la langue active -----------
# Usage : echo "$(t welcome_title)"
#
# Si la clé n'existe pas, retourne la clé elle-même (pour debug).
t() {
    local key=$1
    local var_name="t_${SIEM_LANG}_${key}"

    # Récupère la valeur de la variable dynamiquement
    local value="${!var_name}"

    # Si la traduction n'existe pas, fallback sur le français
    if [ -z "$value" ]; then
        var_name="t_fr_${key}"
        value="${!var_name}"
    fi

    # Si toujours rien, retourne la clé (pour debug)
    if [ -z "$value" ]; then
        echo "[MISSING TRANSLATION: $key]"
    else
        echo "$value"
    fi
}

# ============================================================================
# SÉLECTION DE LA LANGUE
# ============================================================================

# --- select_language : Demande à l'utilisateur de choisir la langue -------
# Met à jour la variable globale SIEM_LANG.
# Cette fonction est appelée au tout début du script principal.
select_language() {
    local choice

    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║  $(t_en_fallback select_language)     ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    echo "  [1] Français"
    echo "  [2] English"
    echo ""

    while true; do
        echo -n "Votre choix / Your choice [1/2] : "
        read -r choice

        case "$choice" in
            1|fr|FR)
                SIEM_LANG="fr"
                export SIEM_LANG
                echo ""
                echo "✓ Langue sélectionnée : Français"
                return 0
                ;;
            2|en|EN)
                SIEM_LANG="en"
                export SIEM_LANG
                echo ""
                echo "✓ Language selected: English"
                return 0
                ;;
            *)
                echo "❌ Choix invalide / Invalid choice"
                ;;
        esac
    done
}

# --- t_en_fallback : Affiche le texte bilingue (utilisé avant sélection) --
# Utilisé pour l'écran de sélection de langue (on ne sait pas encore).
t_en_fallback() {
    local key=$1
    local fr_var="t_fr_${key}"
    local en_var="t_en_${key}"

    echo "${!fr_var} / ${!en_var}"
}

# ============================================================================
# Fin de core/langue.sh
# ============================================================================
