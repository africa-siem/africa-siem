#!/bin/bash
# ============================================================================
# SIEM AFRICA - Script d'installation Module 1 depuis GitHub
# ============================================================================
#
# 3 modes d'utilisation :
#
#   1. Installation LITE (sans Dashboard Wazuh) :
#      curl -sSL https://raw.githubusercontent.com/africa-siem/africa-siem/main/installation/bootstrap.sh | sudo bash -s -- --lite
#
#   2. Installation FULL (avec Dashboard Wazuh) :
#      curl -sSL https://raw.githubusercontent.com/africa-siem/africa-siem/main/installation/bootstrap.sh | sudo bash -s -- --full
#
#   3. Menu interactif (choix lite/full au lancement) :
#      curl -sSL https://raw.githubusercontent.com/africa-siem/africa-siem/main/installation/bootstrap.sh | sudo bash
#
# ============================================================================

# --- Couleurs ------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# --- Configuration -------------------------------------------------------
readonly GITHUB_USER="africa-siem"
readonly GITHUB_REPO="africa-siem"
readonly GITHUB_BRANCH="main"
readonly MODULE_DIR="installation"
readonly INSTALL_DIR="/opt/siem-africa"
readonly TEMP_DIR="/tmp/siem-africa-install"

# --- Parse des arguments -------------------------------------------------
INSTALL_MODE="menu"  # par défaut : menu interactif

for arg in "$@"; do
    case "$arg" in
        --lite|-l)
            INSTALL_MODE="lite"
            ;;
        --full|-f)
            INSTALL_MODE="full"
            ;;
        --menu|-m)
            INSTALL_MODE="menu"
            ;;
        --help|-h)
            echo "Usage: bootstrap.sh [--lite|--full|--menu]"
            echo ""
            echo "Options:"
            echo "  --lite, -l   Installation LITE (sans Dashboard Wazuh)"
            echo "  --full, -f   Installation FULL (avec Dashboard Wazuh)"
            echo "  --menu, -m   Menu interactif (défaut)"
            echo "  --help, -h   Affiche cette aide"
            exit 0
            ;;
        *)
            # Argument inconnu, on ignore
            ;;
    esac
done

# --- Bannière ------------------------------------------------------------
clear
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}  ${BOLD}SIEM AFRICA - Installation Module 1${RESET}                ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  Téléchargement depuis GitHub et installation          ${CYAN}║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${RESET}"
echo ""

# Affichage du mode choisi
case "$INSTALL_MODE" in
    lite)
        echo -e "  ${GREEN}📦 Mode sélectionné : LITE${RESET}"
        echo -e "     • Snort IDS + Wazuh Manager"
        echo -e "     • RAM minimum : 4 GB"
        ;;
    full)
        echo -e "  ${GREEN}📦 Mode sélectionné : FULL (all-in-one)${RESET}"
        echo -e "     • Snort + Wazuh Manager + Indexer + Dashboard"
        echo -e "     • RAM minimum : 8 GB"
        ;;
    menu)
        echo -e "  ${YELLOW}📦 Mode sélectionné : MENU INTERACTIF${RESET}"
        echo -e "     • Vous choisirez LITE ou FULL au lancement"
        ;;
esac
echo ""

# --- Vérification root ---------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}❌ Ce script doit être exécuté en tant que root${RESET}"
    echo ""
    echo "Relancez avec sudo, par exemple :"
    echo "  curl -sSL https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/${MODULE_DIR}/bootstrap.sh | sudo bash -s -- --${INSTALL_MODE}"
    exit 1
fi

# --- Vérification connexion ----------------------------------------------
echo -e "${CYAN}[1/5]${RESET} Vérification de la connexion internet..."
if ! ping -c 1 -W 3 github.com >/dev/null 2>&1; then
    echo -e "${RED}❌ Pas de connexion à GitHub${RESET}"
    echo "Vérifiez votre réseau et le DNS"
    exit 1
fi
echo -e "${GREEN}✓${RESET} Connexion OK"
echo ""

# --- Installation des prérequis -----------------------------------------
echo -e "${CYAN}[2/5]${RESET} Installation des prérequis (curl, wget, unzip)..."
DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl wget unzip 2>/dev/null
echo -e "${GREEN}✓${RESET} Prérequis installés"
echo ""

# --- Téléchargement du repo ---------------------------------------------
echo -e "${CYAN}[3/5]${RESET} Téléchargement depuis GitHub..."
echo "       URL : https://github.com/${GITHUB_USER}/${GITHUB_REPO}"

rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR" || exit 1

DOWNLOAD_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.zip"

if ! curl -fsSL -o "repo.zip" "$DOWNLOAD_URL"; then
    echo -e "${RED}❌ Échec du téléchargement${RESET}"
    echo "   URL : $DOWNLOAD_URL"
    echo ""
    echo "Vérifications :"
    echo "  1. Repo public ? https://github.com/${GITHUB_USER}/${GITHUB_REPO}"
    echo "  2. Branche '${GITHUB_BRANCH}' existante ?"
    exit 1
fi

size_kb=$(du -k repo.zip | cut -f1)
if [ "$size_kb" -lt 10 ]; then
    echo -e "${RED}❌ Fichier trop petit ($size_kb KB)${RESET}"
    exit 1
fi

echo -e "${GREEN}✓${RESET} Téléchargé ($size_kb KB)"
echo ""

# --- Décompression ------------------------------------------------------
echo -e "${CYAN}[4/5]${RESET} Décompression..."

if ! unzip -q repo.zip; then
    echo -e "${RED}❌ Échec de la décompression${RESET}"
    exit 1
fi

EXTRACTED_DIR="${GITHUB_REPO}-${GITHUB_BRANCH}"
SOURCE_DIR="${EXTRACTED_DIR}/${MODULE_DIR}"

if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${RED}❌ Dossier '${MODULE_DIR}' introuvable dans le repo${RESET}"
    echo ""
    echo "Contenu du repo :"
    ls -la "$EXTRACTED_DIR" 2>/dev/null | head -20
    exit 1
fi

# Vérifier la présence du script à exécuter selon le mode
case "$INSTALL_MODE" in
    lite)
        TARGET_SCRIPT="install-lite.sh"
        ;;
    full)
        TARGET_SCRIPT="install-full.sh"
        ;;
    menu)
        TARGET_SCRIPT="install.sh"
        ;;
esac

if [ ! -f "${SOURCE_DIR}/${TARGET_SCRIPT}" ]; then
    echo -e "${RED}❌ ${TARGET_SCRIPT} introuvable dans ${MODULE_DIR}/${RESET}"
    echo ""
    echo "Contenu de ${MODULE_DIR}/ :"
    ls -la "$SOURCE_DIR" 2>/dev/null | head -20
    exit 1
fi

echo -e "${GREEN}✓${RESET} Fichiers extraits"
echo ""

# --- Installation dans /opt/siem-africa --------------------------------
echo -e "${CYAN}[5/5]${RESET} Installation dans ${INSTALL_DIR}/..."

mkdir -p "$INSTALL_DIR/module-1"

cp -r "$SOURCE_DIR/"* "$INSTALL_DIR/module-1/" 2>/dev/null
cp -r "$SOURCE_DIR/".* "$INSTALL_DIR/module-1/" 2>/dev/null || true

# Rendre les scripts exécutables
find "$INSTALL_DIR/module-1" -name "*.sh" -exec chmod +x {} \;

echo -e "${GREEN}✓${RESET} Copié dans ${INSTALL_DIR}/module-1/"
echo ""

# --- Nettoyage ----------------------------------------------------------
rm -rf "$TEMP_DIR"

# --- Lancement du script approprié --------------------------------------
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║${RESET}  ${GREEN}✓ Téléchargement terminé${RESET}                              ${CYAN}║${RESET}"
echo -e "${CYAN}║${RESET}  Lancement de l'installation...                       ${CYAN}║${RESET}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${RESET}"
echo ""

sleep 2

cd "$INSTALL_DIR/module-1" || exit 1

# Lancement du bon script selon le mode
case "$INSTALL_MODE" in
    lite)
        echo -e "${GREEN}🚀 Lancement de l'installation LITE...${RESET}"
        exec ./install-lite.sh
        ;;
    full)
        echo -e "${GREEN}🚀 Lancement de l'installation FULL...${RESET}"
        exec ./install-full.sh
        ;;
    menu)
        echo -e "${GREEN}🚀 Lancement du menu interactif...${RESET}"
        exec ./install.sh
        ;;
esac
