#!/bin/bash
#===============================================================================
#
#          FILE: install_all.sh
#
#   DESCRIPTION: SIEM Africa - Module 1 - Menu interactif LITE/FULL
#
#         USAGE: sudo ./install_all.sh
#
#   Ce script propose un menu interactif :
#     - Choix de la langue (FR / EN)
#     - Choix du mode d'installation (LITE / FULL)
#   Puis lance le script correspondant.
#
#   ⚠️  Ce script nécessite un terminal interactif (pas de curl | bash).
#   Pour installation non-interactive, utiliser directement :
#     sudo ./install_lite.sh  ou  sudo ./install_full.sh
#
#===============================================================================

# NOTE: set -e désactivé (provoque des plantages silencieux sur && / conditions)

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ -z "$SCRIPT_DIR" ]; then
    SCRIPT_DIR="/tmp"
fi

# URL du repo GitHub (pour téléchargement des scripts si absents localement)
GITHUB_BASE="https://raw.githubusercontent.com/africa-siem/africa-siem/main/installation"

#---------------------------------------
# Vérification root
#---------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ Ce script doit être exécuté avec sudo.${NC}"
    echo ""
    echo "   Relancez : sudo ./install_all.sh"
    exit 1
fi

#---------------------------------------
# Vérification terminal interactif
#---------------------------------------
if [ ! -t 0 ]; then
    echo -e "${RED}✗ Ce script nécessite un terminal interactif.${NC}"
    echo ""
    echo "   ⚠️  Vous avez probablement lancé via 'curl | sudo bash'."
    echo ""
    echo "   Utilisez plutôt l'une de ces méthodes :"
    echo ""
    echo "   1. Téléchargez d'abord puis exécutez :"
    echo "      curl -sL $GITHUB_BASE/install_all.sh -o /tmp/install.sh"
    echo "      sudo bash /tmp/install.sh"
    echo ""
    echo "   2. Ou lancez directement un mode sans menu :"
    echo "      curl -sL $GITHUB_BASE/install_lite.sh | sudo bash"
    echo "      curl -sL $GITHUB_BASE/install_full.sh | sudo bash"
    echo ""
    exit 1
fi

#---------------------------------------
# Banner
#---------------------------------------
clear 2>/dev/null || true
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║         🛡️   SIEM AFRICA - MODULE 1                             ║"
echo "║                                                                  ║"
echo "║              Snort IDS + Wazuh SIEM                              ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

#---------------------------------------
# Choix de la langue
#---------------------------------------
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}Choix de la langue / Language selection${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "    [1] Français (défaut)"
echo "    [2] English"
echo ""
echo -n "  → Choix [1/2] : "
read -r LANG_CHOICE

LANG_CODE="fr"
case "$LANG_CHOICE" in
    2|en|EN) LANG_CODE="en" ;;
    *) LANG_CODE="fr" ;;
esac

echo ""

#---------------------------------------
# Texte bilingue
#---------------------------------------
if [ "$LANG_CODE" = "en" ]; then
    T_MODE_CHOICE="INSTALLATION MODE SELECTION"
    T_LITE="Snort + Wazuh Manager only (command-line)"
    T_LITE_REQ="Minimum: 2 GB RAM, 15 GB disk, 1 CPU"
    T_LITE_USE="Best for: light servers, no web dashboard"
    T_FULL="Snort + Wazuh full (Manager + Indexer + Dashboard)"
    T_FULL_REQ="Minimum: 4 GB RAM, 30 GB disk, 2 CPUs"
    T_FULL_USE="Best for: production, web dashboard included"
    T_CHOICE="Your choice [1/2]:"
    T_INVALID="Invalid choice. Restart the script."
    T_STARTING="Starting"
    T_INSTALL="installation..."
    T_NOT_FOUND="not found, downloading..."
    T_DL_FAILED="Download failed"
else
    T_MODE_CHOICE="CHOIX DU MODE D'INSTALLATION"
    T_LITE="Snort + Wazuh Manager seul (ligne de commande)"
    T_LITE_REQ="Minimum : 2 Go RAM, 15 Go disque, 1 CPU"
    T_LITE_USE="Idéal pour : serveurs légers, sans dashboard web"
    T_FULL="Snort + Wazuh complet (Manager + Indexer + Dashboard)"
    T_FULL_REQ="Minimum : 4 Go RAM, 30 Go disque, 2 CPU"
    T_FULL_USE="Idéal pour : production, dashboard web inclus"
    T_CHOICE="Votre choix [1/2] :"
    T_INVALID="Choix invalide. Relancez le script."
    T_STARTING="Démarrage de l'installation"
    T_INSTALL=""
    T_NOT_FOUND="introuvable, téléchargement..."
    T_DL_FAILED="Échec du téléchargement"
fi

#---------------------------------------
# Menu mode lite/full
#---------------------------------------
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}$T_MODE_CHOICE${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}[1] LITE${NC} - $T_LITE"
echo -e "           ${CYAN}$T_LITE_REQ${NC}"
echo -e "           ${CYAN}$T_LITE_USE${NC}"
echo ""
echo -e "  ${GREEN}[2] FULL${NC} - $T_FULL"
echo -e "           ${CYAN}$T_FULL_REQ${NC}"
echo -e "           ${CYAN}$T_FULL_USE${NC}"
echo ""
echo -n "  → $T_CHOICE "
read -r MODE_CHOICE
echo ""

MODE_NAME=""
SCRIPT_NAME=""
case "$MODE_CHOICE" in
    1|lite|LITE)
        MODE_NAME="LITE"
        SCRIPT_NAME="install_lite.sh"
        ;;
    2|full|FULL)
        MODE_NAME="FULL"
        SCRIPT_NAME="install_full.sh"
        ;;
    *)
        echo -e "${RED}✗ $T_INVALID${NC}"
        exit 1
        ;;
esac

#---------------------------------------
# Recherche du script cible (local ou download)
#---------------------------------------
TARGET_SCRIPT="${SCRIPT_DIR}/${SCRIPT_NAME}"

if [ ! -f "$TARGET_SCRIPT" ]; then
    echo -e "${YELLOW}  ℹ  ${SCRIPT_NAME} $T_NOT_FOUND${NC}"
    TARGET_SCRIPT="/tmp/${SCRIPT_NAME}"
    if ! curl -sL "${GITHUB_BASE}/${SCRIPT_NAME}" -o "$TARGET_SCRIPT"; then
        echo -e "${RED}✗ $T_DL_FAILED : ${GITHUB_BASE}/${SCRIPT_NAME}${NC}"
        exit 1
    fi
fi

if [ ! -f "$TARGET_SCRIPT" ]; then
    echo -e "${RED}✗ ${SCRIPT_NAME} introuvable après téléchargement.${NC}"
    exit 1
fi

chmod +x "$TARGET_SCRIPT" 2>/dev/null

#---------------------------------------
# Lancement
#---------------------------------------
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${BOLD}$T_STARTING $MODE_NAME $T_INSTALL${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
sleep 1

# Lancer le script cible avec la langue en argument
exec bash "$TARGET_SCRIPT" --lang "$LANG_CODE"
