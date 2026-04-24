#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# clean-install.sh — Purge complète + installation fraîche
# ============================================================================
#
# Ce script fait en UNE SEULE commande :
#   1. Purge complète de toute installation précédente (Snort, Wazuh, etc.)
#   2. Installation fraîche selon le mode choisi
#
# Utilisation :
#   sudo ./clean-install.sh          # menu interactif (lite/full)
#   sudo ./clean-install.sh lite     # directement mode lite
#   sudo ./clean-install.sh full     # directement mode full
#
# Ce script est LA solution au problème "l'install plante sur un système
# où il y a déjà des traces d'installations précédentes".
#
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Chargement des fonctions utilitaires
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/logging.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/langue.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/core/cleanup.sh"

# ============================================================================
# VÉRIFICATION ROOT
# ============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo ""
    echo "❌ ERREUR : Ce script doit être exécuté avec sudo."
    echo ""
    echo "   Relancez avec : sudo ./clean-install.sh"
    echo ""
    exit 1
fi

# ============================================================================
# ARGUMENT : MODE (lite | full)
# ============================================================================

MODE="${1:-}"

# Initialisation du log
log_init

log_banner "SIEM AFRICA — CLEAN INSTALL"

log_info "Ce script va :"
log_info "  1. Arrêter tous les services Snort, Wazuh, Filebeat"
log_info "  2. Supprimer tous les paquets et fichiers associés"
log_info "  3. Sauvegarder les anciens fichiers d'état dans /var/backups/"
log_info "  4. Relancer une installation fraîche"
echo ""

# ============================================================================
# CONFIRMATION
# ============================================================================

log_warning "ATTENTION : Toutes les données SIEM existantes seront supprimées."
log_warning "            Un backup sera créé dans /var/backups/siem-africa-old-*"
echo ""
echo -n "Tapez 'OUI' pour continuer : "
read -r CONFIRM

if [ "$CONFIRM" != "OUI" ]; then
    log_info "Opération annulée."
    exit 0
fi

# ============================================================================
# PHASE 1 : PURGE
# ============================================================================

echo ""
log_step "PHASE 1" "Purge complète de l'installation existante"
echo ""

cleanup_all

log_separator

# Vérification post-purge
log_info "Vérification que tout est bien propre..."
if ! verify_cleanup; then
    log_warning "Des résidus existent encore. Tentative de nettoyage forcé..."
    sleep 2
    cleanup_all
    if ! verify_cleanup; then
        log_error "Impossible de nettoyer complètement. Intervention manuelle nécessaire."
        log_info "Consultez les logs : ${LOG_FILE}"
        exit 1
    fi
fi

log_success "Système propre, prêt pour une nouvelle installation"
echo ""

# ============================================================================
# PHASE 2 : CHOIX DU MODE
# ============================================================================

if [ -z "$MODE" ]; then
    # Pas d'argument → menu interactif
    echo ""
    echo "Mode d'installation :"
    echo "  [1] LITE  (4 GB RAM, Snort + Wazuh Manager seul)"
    echo "  [2] FULL  (8 GB RAM, all-in-one avec Dashboard)"
    echo ""
    echo -n "Votre choix [1/2] : "
    read -r CHOICE

    case "$CHOICE" in
        1|lite|LITE) MODE="lite" ;;
        2|full|FULL) MODE="full" ;;
        *)
            log_error "Choix invalide"
            exit 1
            ;;
    esac
fi

# ============================================================================
# PHASE 3 : INSTALLATION FRAÎCHE
# ============================================================================

echo ""
log_step "PHASE 2" "Installation fraîche (mode ${MODE})"
echo ""

TARGET_SCRIPT=""
if [ "$MODE" = "lite" ]; then
    TARGET_SCRIPT="${SCRIPT_DIR}/install-lite.sh"
elif [ "$MODE" = "full" ]; then
    TARGET_SCRIPT="${SCRIPT_DIR}/install-full.sh"
else
    log_error "Mode inconnu : ${MODE}"
    exit 1
fi

if [ ! -f "$TARGET_SCRIPT" ]; then
    log_error "Script d'installation introuvable : ${TARGET_SCRIPT}"
    log_error "Vérifiez que les fichiers du Module 1 sont bien présents."
    exit 1
fi

# Rendre exécutable si besoin
chmod +x "$TARGET_SCRIPT"

# Lancement — on n'utilise PAS exec car on veut afficher un message après
if "$TARGET_SCRIPT"; then
    echo ""
    log_banner "CLEAN-INSTALL TERMINÉ AVEC SUCCÈS"
    echo ""
    log_info "Votre installation SIEM Africa est prête."
    log_info "Consultez le résumé : sudo cat /etc/siem-africa/RESUME.txt"
else
    echo ""
    log_error "L'installation fraîche a échoué."
    log_error "Consultez les logs : ${LOG_FILE}"
    exit 1
fi

exit 0

# ============================================================================
# Fin de clean-install.sh
# ============================================================================
