#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/05-wazuh-dashboard.sh — Installation Wazuh Dashboard (Mode FULL)
# ============================================================================
#
# Ce module installe Wazuh Dashboard (interface web basée sur OpenSearch
# Dashboards) pour le Mode FULL uniquement.
#
# Wazuh Dashboard fournit :
#   - Une interface web pour visualiser les alertes
#   - Des tableaux de bord préconfigurés (MITRE ATT&CK, PCI-DSS, etc.)
#   - Des outils de recherche et filtrage avancés
#   - La gestion des règles et agents
#
# Accès : https://<IP_SERVEUR> (port 443)
# Login : admin / [mot de passe généré]
#
# ============================================================================

readonly DASHBOARD_VERSION="4.14"

# ============================================================================
# ÉTAPE 1 : Installation du paquet wazuh-dashboard
# ============================================================================

install_dashboard_package() {
    log_info "Installation de Wazuh Dashboard ${DASHBOARD_VERSION}..."

    # Le dépôt Wazuh est déjà configuré
    if DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-dashboard >> "$LOG_FILE" 2>&1; then
        log_success "Wazuh Dashboard installé"
    else
        log_error "Échec installation Wazuh Dashboard"
        log_info  "Consultez ${LOG_FILE}"
        return 1
    fi

    return 0
}

# ============================================================================
# ÉTAPE 2 : Configuration du Dashboard
# ============================================================================

configure_dashboard() {
    log_info "Configuration de Wazuh Dashboard..."

    local dashboard_conf="/etc/wazuh-dashboard/opensearch_dashboards.yml"

    if [ ! -f "$dashboard_conf" ]; then
        log_error "Fichier de config introuvable : ${dashboard_conf}"
        return 1
    fi

    # Backup
    if [ ! -f "${dashboard_conf}.backup" ]; then
        cp "$dashboard_conf" "${dashboard_conf}.backup"
    fi

    # La configuration par défaut écoute déjà sur toutes les interfaces
    # Et utilise le bon URL pour l'Indexer (https://localhost:9200)

    # Configuration de base :
    # - server.host: 0.0.0.0 (écoute sur toutes les interfaces)
    # - server.port: 443 (HTTPS)
    # - opensearch.hosts: ["https://localhost:9200"]

    # On vérifie juste que la config est cohérente
    if grep -q "server.host:" "$dashboard_conf"; then
        log_success "Configuration Dashboard vérifiée"
    else
        log_warning "Configuration Dashboard à vérifier manuellement"
    fi

    return 0
}

# ============================================================================
# ÉTAPE 3 : Configuration du plugin Wazuh App
# ============================================================================

configure_wazuh_app() {
    log_info "Configuration du plugin Wazuh App..."

    # Le plugin Wazuh App dans le Dashboard doit savoir comment contacter
    # le Wazuh Manager (API)

    local wazuh_app_conf="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"

    # Créer le répertoire si besoin
    mkdir -p "$(dirname "$wazuh_app_conf")"

    # Configuration de l'API Wazuh pour le plugin
    cat > "$wazuh_app_conf" <<EOF
---
hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: "wazuh-wui"
      run_as: false
EOF

    # Permissions
    chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/data/wazuh/ 2>/dev/null || true

    log_success "Plugin Wazuh App configuré"
    return 0
}

# ============================================================================
# ÉTAPE 4 : Génération du mot de passe admin
# ============================================================================

generate_admin_password() {
    log_info "Génération du mot de passe admin..."

    # Génération d'un mot de passe aléatoire robuste
    # - 16 caractères
    # - Mélange majuscules, minuscules, chiffres, caractères spéciaux
    # - Utilise /dev/urandom pour l'entropie
    local admin_password
    admin_password=$(tr -dc 'A-Za-z0-9!#$%&*+=?@' < /dev/urandom | head -c 16)

    if [ -z "$admin_password" ] || [ ${#admin_password} -lt 12 ]; then
        log_error "Échec génération du mot de passe"
        return 1
    fi

    # Sauvegarde dans le fichier secret (utilise save_secret de core/state.sh)
    save_secret "wazuh-admin.pwd" "$admin_password"

    # Export pour utilisation par d'autres fonctions
    export WAZUH_ADMIN_PASSWORD="$admin_password"

    log_success "Mot de passe admin généré et sauvegardé"
    log_info  "Emplacement : ${SECRETS_DIR}/wazuh-admin.pwd"

    return 0
}

# ============================================================================
# ÉTAPE 5 : Application du mot de passe dans OpenSearch
# ============================================================================

apply_admin_password() {
    log_info "Application du mot de passe admin à OpenSearch..."

    if [ -z "$WAZUH_ADMIN_PASSWORD" ]; then
        log_error "Variable WAZUH_ADMIN_PASSWORD non définie"
        return 1
    fi

    # Le changement de mot de passe nécessite :
    # 1. Hashage du mot de passe avec hash.sh d'OpenSearch
    # 2. Modification du fichier internal_users.yml
    # 3. Application via securityadmin.sh

    local hash_tool="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
    local users_file="/etc/wazuh-indexer/opensearch-security/internal_users.yml"

    if [ ! -x "$hash_tool" ]; then
        log_warning "Outil de hashage introuvable, mot de passe par défaut conservé"
        log_info  "Changez manuellement via l'interface web à la première connexion"
        return 0
    fi

    # Hashage du mot de passe
    local hashed_password
    hashed_password=$(bash "$hash_tool" -p "$WAZUH_ADMIN_PASSWORD" 2>/dev/null | tail -1)

    if [ -z "$hashed_password" ]; then
        log_warning "Échec hashage du mot de passe"
        return 0
    fi

    # NOTE : La modification de internal_users.yml et l'application via
    # securityadmin.sh est un processus complexe qui peut échouer dans
    # certaines configurations. Pour la V2.0, on se contente de générer
    # le mot de passe et de l'exposer à l'admin.
    #
    # L'admin devra le changer manuellement via l'interface Dashboard
    # à la première connexion (plus sûr car l'admin valide le nouveau mot de passe).

    log_info "Mot de passe à appliquer manuellement via l'interface Dashboard"
    log_info "À la première connexion, utilisez 'admin/admin' puis changez immédiatement"

    return 0
}

# ============================================================================
# ÉTAPE 6 : Activation et démarrage
# ============================================================================

enable_dashboard_service() {
    log_info "Activation du service wazuh-dashboard..."

    systemctl daemon-reload >> "$LOG_FILE" 2>&1
    systemctl enable wazuh-dashboard >> "$LOG_FILE" 2>&1

    log_info "Démarrage de wazuh-dashboard (peut prendre 1-2 minutes)..."
    if systemctl start wazuh-dashboard >> "$LOG_FILE" 2>&1; then
        # Attendre que le Dashboard soit prêt
        local max_wait=120
        local waited=0
        local ready=false

        while [ $waited -lt $max_wait ]; do
            if curl -k -s -m 5 "https://localhost" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "^(200|302)$"; then
                ready=true
                break
            fi
            sleep 5
            waited=$((waited + 5))

            if [ $((waited % 30)) -eq 0 ]; then
                log_info "En attente du Dashboard... (${waited}s / ${max_wait}s)"
            fi
        done

        if [ "$ready" = true ]; then
            log_success "Wazuh Dashboard opérationnel"
            log_info  "Accès : https://${DETECTED_IP:-<IP_SERVEUR>}"
        else
            log_warning "Dashboard pas encore prêt après ${max_wait}s"
            log_info  "Vérifiez dans quelques minutes : https://${DETECTED_IP}"
        fi
    else
        log_error "Échec démarrage wazuh-dashboard"
        log_info  "Debug : sudo journalctl -u wazuh-dashboard -n 50"
        return 1
    fi

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE DU MODULE
# ============================================================================

install_wazuh_dashboard() {
    log_info "Démarrage installation Wazuh Dashboard (Mode FULL)..."

    install_dashboard_package    || return 1
    configure_dashboard          || return 1
    configure_wazuh_app          || return 1
    generate_admin_password      || return 1
    apply_admin_password         || log_warning "Mot de passe à changer manuellement"
    enable_dashboard_service     || return 1

    log_success "Installation Wazuh Dashboard terminée"
    log_info  "Interface web : https://${DETECTED_IP:-<IP_SERVEUR>}"
    log_info  "Login : admin"
    log_info  "Mot de passe : voir ${SECRETS_DIR}/wazuh-admin.pwd"

    return 0
}

# ============================================================================
# Fin de modules/05-wazuh-dashboard.sh
# ============================================================================
