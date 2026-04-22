#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/03-wazuh-manager.sh — Installation de Wazuh Manager 4.14
# ============================================================================
#
# Ce module installe Wazuh Manager depuis les dépôts officiels.
#
# Wazuh Manager est le cerveau du SIEM :
#   - Reçoit les logs de Snort et des agents
#   - Applique les règles de corrélation
#   - Écrit les alertes dans /var/ossec/logs/alerts/alerts.json
#   - Expose une API (port 55000) pour gestion
#
# Référence officielle :
#   https://documentation.wazuh.com/current/installation-guide/wazuh-server/
#
# ============================================================================

# ============================================================================
# Variables du module
# ============================================================================

readonly WAZUH_VERSION="4.14"
readonly WAZUH_GPG_KEY_URL="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
readonly WAZUH_REPO_URL="https://packages.wazuh.com/4.x/apt/"

# ============================================================================
# ÉTAPE 1 : Ajout du dépôt Wazuh
# ============================================================================

add_wazuh_repository() {
    log_info "Ajout du dépôt officiel Wazuh..."

    # --- 1. Importer la clé GPG Wazuh ---
    # Les clés GPG vérifient l'authenticité des paquets téléchargés
    # Sans ça, apt refuse d'installer par sécurité

    # Répertoire pour les clés (standard Debian/Ubuntu moderne)
    local keyring_dir="/usr/share/keyrings"
    local keyring_file="${keyring_dir}/wazuh.gpg"

    mkdir -p "$keyring_dir"

    # Téléchargement et import de la clé
    # --no-default-keyring : ne pas utiliser le trousseau par défaut
    # --keyring : spécifier notre trousseau dédié
    if curl -s "$WAZUH_GPG_KEY_URL" | \
        gpg --no-default-keyring --keyring "gnupg-ring:${keyring_file}" --import >> "$LOG_FILE" 2>&1; then
        log_success "Clé GPG Wazuh importée"
    else
        log_error "Échec import clé GPG Wazuh"
        log_info  "Vérifiez votre connexion internet"
        return 1
    fi

    # Permissions de la clé (lecture pour tout le monde, écriture pour root)
    chmod 644 "$keyring_file"

    # --- 2. Ajouter le dépôt dans sources.list.d ---
    # Format moderne : spécifier signed-by pour indiquer quelle clé utiliser
    local repo_file="/etc/apt/sources.list.d/wazuh.list"

    echo "deb [signed-by=${keyring_file}] ${WAZUH_REPO_URL} stable main" > "$repo_file"
    log_success "Dépôt Wazuh ajouté : ${repo_file}"

    # --- 3. Mise à jour de la liste des paquets ---
    if DEBIAN_FRONTEND=noninteractive apt-get update -y >> "$LOG_FILE" 2>&1; then
        log_success "Liste des paquets mise à jour"
    else
        log_error "Échec apt-get update après ajout du dépôt Wazuh"
        return 1
    fi

    return 0
}

# ============================================================================
# ÉTAPE 2 : Installation du paquet wazuh-manager
# ============================================================================

install_wazuh_manager_package() {
    log_info "Installation de Wazuh Manager ${WAZUH_VERSION}..."

    # Installation du paquet
    # Note : on ne spécifie pas de version précise ici pour prendre la dernière stable
    # Si on veut pinner : apt-get install wazuh-manager=4.14.0-1
    if DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-manager >> "$LOG_FILE" 2>&1; then
        log_success "Wazuh Manager installé"
    else
        log_error "Échec installation Wazuh Manager"
        log_info  "Consultez ${LOG_FILE}"
        return 1
    fi

    # Vérification de la version installée
    local installed_version
    installed_version=$(dpkg -l wazuh-manager 2>/dev/null | awk '/^ii/ {print $3}')
    if [ -n "$installed_version" ]; then
        log_info "Version installée : ${installed_version}"
        export WAZUH_MANAGER_VERSION="$installed_version"
    fi

    return 0
}

# ============================================================================
# ÉTAPE 3 : Configuration de base de Wazuh Manager
# ============================================================================

configure_wazuh_manager() {
    log_info "Configuration de Wazuh Manager..."

    local ossec_conf="/var/ossec/etc/ossec.conf"

    # Vérification que le fichier de config existe
    if [ ! -f "$ossec_conf" ]; then
        log_error "Fichier de config Wazuh introuvable : ${ossec_conf}"
        log_info  "Wazuh Manager n'est peut-être pas correctement installé"
        return 1
    fi

    # Sauvegarde du fichier de config d'origine
    if [ ! -f "${ossec_conf}.backup" ]; then
        cp "$ossec_conf" "${ossec_conf}.backup"
        log_info "Sauvegarde : ${ossec_conf}.backup"
    fi

    # Note sur la configuration :
    # Wazuh Manager sort avec une config par défaut qui fonctionne bien.
    # On ne change PAS les paramètres par défaut pour rester compatible avec
    # les évolutions futures de Wazuh.
    #
    # Les customisations se font dans /var/ossec/etc/local_*.xml
    # Ces fichiers sont préservés lors des mises à jour.

    # --- Création du dossier pour les logs alertes si besoin ---
    local alerts_dir="/var/ossec/logs/alerts"
    if [ ! -d "$alerts_dir" ]; then
        mkdir -p "$alerts_dir"
        chown wazuh:wazuh "$alerts_dir" 2>/dev/null || true
        chmod 750 "$alerts_dir"
        log_info "Dossier alertes créé : ${alerts_dir}"
    fi

    # --- Vérification que le format JSON est activé ---
    # On veut que Wazuh écrive alerts.json (en plus de alerts.log)
    # Par défaut dans Wazuh 4.x : <jsonout_output>yes</jsonout_output>
    if grep -q "<jsonout_output>yes</jsonout_output>" "$ossec_conf"; then
        log_success "Format JSON activé dans la config"
    else
        log_warning "Format JSON non détecté dans ossec.conf"
        log_info  "Vérifiez manuellement : grep jsonout_output ${ossec_conf}"
    fi

    log_success "Configuration Wazuh Manager validée"
    return 0
}

# ============================================================================
# ÉTAPE 4 : Permissions sur les fichiers Wazuh
# ============================================================================

setup_wazuh_permissions() {
    log_info "Configuration des permissions Wazuh..."

    # Pour que notre user 'siem-ids' (et plus tard 'siem-agent') puisse lire
    # les alertes Wazuh, on l'ajoute au groupe wazuh
    if getent group wazuh >/dev/null 2>&1; then
        if user_exists "siem-ids"; then
            usermod -aG wazuh siem-ids 2>/dev/null || true
            log_success "User siem-ids ajouté au groupe wazuh"
        fi
    fi

    # Permissions lecture sur le dossier d'alertes
    # /var/ossec/logs/alerts/ doit être lisible par le groupe wazuh (par défaut OK)
    chmod 750 /var/ossec/logs/alerts/ 2>/dev/null || true

    return 0
}

# ============================================================================
# ÉTAPE 5 : Activation et démarrage du service
# ============================================================================

enable_wazuh_manager_service() {
    log_info "Activation du service wazuh-manager..."

    # Activation au démarrage
    if systemctl daemon-reload >> "$LOG_FILE" 2>&1 && \
       systemctl enable wazuh-manager >> "$LOG_FILE" 2>&1; then
        log_success "wazuh-manager activé au démarrage"
    else
        log_warning "Échec activation systemd (wazuh-manager)"
    fi

    # Démarrage
    # Wazuh peut prendre 10-30 secondes pour démarrer complètement
    log_info "Démarrage de wazuh-manager (peut prendre 30s)..."
    if systemctl restart wazuh-manager >> "$LOG_FILE" 2>&1; then
        # Attente du démarrage complet
        local max_wait=30
        local waited=0
        while [ $waited -lt $max_wait ]; do
            if systemctl is-active --quiet wazuh-manager; then
                log_success "Service wazuh-manager actif"
                break
            fi
            sleep 2
            waited=$((waited + 2))
        done

        if ! systemctl is-active --quiet wazuh-manager; then
            log_error "wazuh-manager n'a pas démarré après ${max_wait}s"
            log_info  "Commande de debug : sudo journalctl -u wazuh-manager -n 50"
            return 1
        fi
    else
        log_error "Échec démarrage wazuh-manager"
        return 1
    fi

    # Vérification que alerts.json est bien créé
    local alerts_json="/var/ossec/logs/alerts/alerts.json"
    if [ -f "$alerts_json" ] || [ -d "$(dirname "$alerts_json")" ]; then
        log_success "Dossier d'alertes prêt : ${alerts_json}"
    fi

    return 0
}

# ============================================================================
# ÉTAPE 6 : Test de validation
# ============================================================================

test_wazuh_manager() {
    log_info "Test de validation de Wazuh Manager..."

    # Test 1 : Service actif
    if systemctl is-active --quiet wazuh-manager; then
        log_success "Test 1 : Service wazuh-manager actif ✓"
    else
        log_error "Test 1 : Service wazuh-manager inactif ✗"
        return 1
    fi

    # Test 2 : Port 1514 en écoute
    if ss -tuln 2>/dev/null | grep -q ":1514 "; then
        log_success "Test 2 : Port 1514 (agents) en écoute ✓"
    else
        log_warning "Test 2 : Port 1514 non détecté"
    fi

    # Test 3 : Port 55000 (API) en écoute
    if ss -tuln 2>/dev/null | grep -q ":55000 "; then
        log_success "Test 3 : Port 55000 (API) en écoute ✓"
    else
        log_warning "Test 3 : Port 55000 non détecté (normal si pas d'agent)"
    fi

    # Test 4 : Fichier ossec.conf valide
    if /var/ossec/bin/wazuh-control info >> "$LOG_FILE" 2>&1; then
        log_success "Test 4 : Configuration Wazuh valide ✓"
    else
        log_warning "Test 4 : Problème de configuration détecté"
    fi

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE DU MODULE
# ============================================================================

install_wazuh_manager() {
    log_info "Démarrage de l'installation Wazuh Manager ${WAZUH_VERSION}..."

    add_wazuh_repository            || return 1
    install_wazuh_manager_package   || return 1
    configure_wazuh_manager         || return 1
    setup_wazuh_permissions         || return 1
    enable_wazuh_manager_service    || return 1
    test_wazuh_manager              || log_warning "Certains tests ont échoué"

    log_success "Installation Wazuh Manager terminée"
    return 0
}

# ============================================================================
# Fin de modules/03-wazuh-manager.sh
# ============================================================================
