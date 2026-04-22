#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# core/os-detect.sh — Détection du système d'exploitation
# ============================================================================
#
# Ce fichier détecte le système d'exploitation et vérifie qu'il est supporté.
# Il définit des variables globales utilisées par les autres scripts pour
# adapter leur comportement selon la distribution.
#
# Variables globales définies :
#   OS_ID          : "ubuntu" ou "debian"
#   OS_VERSION     : "22.04", "24.04", "11", "12"
#   OS_NAME        : Nom complet du système
#   OS_CODENAME    : "jammy", "noble", "bullseye", "bookworm"
#   OS_KERNEL      : Version du noyau Linux
#   OS_ARCH        : Architecture ("x86_64")
#
# Utilisation :
#   source core/os-detect.sh
#   detect_os
#   verify_os_compatible  # quitte avec erreur si non supporté
#
# ============================================================================

# --- Versions supportées --------------------------------------------------
# Liste des couples (distribution, version) officiellement supportés.
# Si tu veux ajouter un OS, édite ces tableaux.
readonly SUPPORTED_UBUNTU_VERSIONS=("22.04" "24.04")
readonly SUPPORTED_DEBIAN_VERSIONS=("11" "12")
readonly SUPPORTED_ARCHITECTURES=("x86_64" "amd64")

# --- detect_os : Détecte le système d'exploitation ------------------------
# Lit /etc/os-release (fichier standard sur tous les Linux modernes).
# Remplit les variables globales OS_ID, OS_VERSION, etc.
#
# Retour :
#   0 si la détection a réussi
#   1 si /etc/os-release est introuvable
detect_os() {
    # Le fichier /etc/os-release est présent sur TOUS les Linux modernes.
    # Il contient des clés standardisées : ID, VERSION_ID, NAME, etc.
    if [ ! -f /etc/os-release ]; then
        log_error "Fichier /etc/os-release introuvable"
        log_error "Impossible de détecter le système d'exploitation"
        return 1
    fi

    # On "source" le fichier pour charger ses variables dans notre shell.
    # Les variables comme $ID, $VERSION_ID seront alors disponibles.
    # shellcheck disable=SC1091
    source /etc/os-release

    # On stocke les valeurs dans nos propres variables pour éviter les collisions
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_NAME="${NAME:-Unknown Linux}"
    OS_CODENAME="${VERSION_CODENAME:-unknown}"

    # Version du noyau (utile pour debug)
    OS_KERNEL=$(uname -r)

    # Architecture (x86_64 est attendu)
    OS_ARCH=$(uname -m)

    # On exporte pour que les sous-scripts y aient accès
    export OS_ID OS_VERSION OS_NAME OS_CODENAME OS_KERNEL OS_ARCH

    return 0
}

# --- is_version_supported : Vérifie si une version est dans une liste -----
# Usage interne (utilisé par verify_os_compatible).
#
# Arguments :
#   $1 : version à vérifier (ex: "22.04")
#   $2..N : liste des versions supportées
#
# Retour : 0 si supporté, 1 sinon
is_version_supported() {
    local version=$1
    shift
    local supported_list=("$@")

    for supported in "${supported_list[@]}"; do
        if [ "$version" = "$supported" ]; then
            return 0
        fi
    done

    return 1
}

# --- verify_os_compatible : Vérifie la compatibilité complète -------------
# Appelle detect_os() puis vérifie :
#   1. L'architecture est supportée (x86_64)
#   2. La distribution est Ubuntu ou Debian
#   3. La version de la distribution est supportée
#
# Si une vérification échoue, quitte le script avec code 1.
verify_os_compatible() {
    # Étape 1 : détection
    if ! detect_os; then
        die "Détection du système impossible"
    fi

    # Affichage des infos détectées
    log_info "Système détecté  : ${OS_NAME} ${OS_VERSION}"
    log_info "Nom de code      : ${OS_CODENAME}"
    log_info "Architecture     : ${OS_ARCH}"
    log_info "Noyau            : ${OS_KERNEL}"

    # Étape 2 : vérification architecture
    if ! is_version_supported "$OS_ARCH" "${SUPPORTED_ARCHITECTURES[@]}"; then
        log_error "Architecture non supportée : ${OS_ARCH}"
        log_error "Architectures supportées : ${SUPPORTED_ARCHITECTURES[*]}"
        log_info  "Support ARM prévu en version 2.1"
        die "Architecture incompatible"
    fi

    # Étape 3 : vérification distribution et version
    case "$OS_ID" in
        ubuntu)
            if is_version_supported "$OS_VERSION" "${SUPPORTED_UBUNTU_VERSIONS[@]}"; then
                log_success "Ubuntu ${OS_VERSION} est supporté officiellement"
                return 0
            else
                log_error "Ubuntu ${OS_VERSION} n'est pas supporté"
                log_info  "Versions Ubuntu supportées : ${SUPPORTED_UBUNTU_VERSIONS[*]}"
                die "Version Ubuntu incompatible"
            fi
            ;;

        debian)
            if is_version_supported "$OS_VERSION" "${SUPPORTED_DEBIAN_VERSIONS[@]}"; then
                log_success "Debian ${OS_VERSION} est supporté officiellement"
                log_warning "Support Debian : compatibilité théorique non testée en conditions réelles"
                return 0
            else
                log_error "Debian ${OS_VERSION} n'est pas supporté"
                log_info  "Versions Debian supportées : ${SUPPORTED_DEBIAN_VERSIONS[*]}"
                die "Version Debian incompatible"
            fi
            ;;

        *)
            log_error "Distribution non supportée : ${OS_ID}"
            log_info  "Distributions supportées :"
            log_info  "  • Ubuntu : ${SUPPORTED_UBUNTU_VERSIONS[*]}"
            log_info  "  • Debian : ${SUPPORTED_DEBIAN_VERSIONS[*]}"

            # Distributions dérivées connues (pour info)
            case "$OS_ID" in
                linuxmint)
                    log_info "Linux Mint est basé sur Ubuntu mais n'est pas officiellement supporté"
                    ;;
                kali|parrot)
                    log_info "${OS_ID} est basé sur Debian mais n'est pas officiellement supporté"
                    ;;
                raspbian)
                    log_info "Raspbian ARM sera supporté en version 2.1"
                    ;;
            esac

            die "Distribution incompatible"
            ;;
    esac
}

# --- is_ubuntu : Retourne 0 si le système est Ubuntu ----------------------
# Usage :
#   if is_ubuntu; then
#       echo "On est sur Ubuntu"
#   fi
is_ubuntu() {
    [ "$OS_ID" = "ubuntu" ]
}

# --- is_debian : Retourne 0 si le système est Debian ----------------------
is_debian() {
    [ "$OS_ID" = "debian" ]
}

# --- is_ubuntu_version : Vérifie si c'est une version Ubuntu spécifique ---
# Usage :
#   if is_ubuntu_version "22.04"; then ...
is_ubuntu_version() {
    local target=$1
    is_ubuntu && [ "$OS_VERSION" = "$target" ]
}

# --- is_debian_version : Vérifie si c'est une version Debian spécifique ---
is_debian_version() {
    local target=$1
    is_debian && [ "$OS_VERSION" = "$target" ]
}

# --- get_os_info_json : Retourne les infos OS au format JSON --------------
# Utilisé pour le fichier d'état et les logs structurés.
get_os_info_json() {
    cat <<EOF
{
  "id": "${OS_ID}",
  "version": "${OS_VERSION}",
  "name": "${OS_NAME}",
  "codename": "${OS_CODENAME}",
  "kernel": "${OS_KERNEL}",
  "architecture": "${OS_ARCH}"
}
EOF
}

# --- get_os_info_yaml : Retourne les infos OS au format YAML --------------
# Pour intégration directe dans le fichier d'état YAML.
get_os_info_yaml() {
    cat <<EOF
  os_id: "${OS_ID}"
  os_name: "${OS_NAME}"
  os_version: "${OS_VERSION}"
  os_codename: "${OS_CODENAME}"
  kernel: "${OS_KERNEL}"
  architecture: "${OS_ARCH}"
EOF
}

# ============================================================================
# Fin de core/os-detect.sh
# ============================================================================
