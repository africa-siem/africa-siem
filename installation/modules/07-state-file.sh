#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/07-state-file.sh — Génération du fichier d'état final
# ============================================================================
#
# Ce module est exécuté EN DERNIER dans l'installation.
# Il génère les deux fichiers documentant l'état du système :
#   - /etc/siem-africa/siem-africa.state.yaml (machine-readable)
#   - /etc/siem-africa/RESUME.txt (human-readable)
#
# Les fonctions utilisées sont définies dans core/state.sh.
#
# ============================================================================

# ============================================================================
# ÉTAPE 1 : Vérification que core/state.sh est bien chargé
# ============================================================================

check_state_functions() {
    # On vérifie que les fonctions nécessaires existent
    # Ces fonctions sont définies dans core/state.sh

    if ! declare -f generate_state_file > /dev/null 2>&1; then
        log_error "Fonction generate_state_file non trouvée"
        log_info  "core/state.sh doit être chargé avec 'source'"
        return 1
    fi

    if ! declare -f generate_resume_file > /dev/null 2>&1; then
        log_error "Fonction generate_resume_file non trouvée"
        return 1
    fi

    return 0
}

# ============================================================================
# ÉTAPE 2 : Génération du fichier d'état YAML
# ============================================================================

create_state_yaml() {
    local mode=$1

    log_info "Génération du fichier d'état YAML..."

    # La fonction generate_state_file est définie dans core/state.sh
    if generate_state_file "$mode"; then
        log_success "Fichier d'état créé : ${STATE_FILE}"

        # Affichage de la taille et des permissions
        if [ -f "$STATE_FILE" ]; then
            local size
            size=$(du -h "$STATE_FILE" | cut -f1)
            local perms
            perms=$(stat -c "%a" "$STATE_FILE")
            log_info  "  Taille : ${size}, Permissions : ${perms}"
        fi
        return 0
    else
        log_error "Échec génération du fichier d'état"
        return 1
    fi
}

# ============================================================================
# ÉTAPE 3 : Génération du RESUME.txt
# ============================================================================

create_resume_txt() {
    local mode=$1

    log_info "Génération du fichier RESUME.txt..."

    if generate_resume_file "$mode"; then
        log_success "Résumé créé : ${RESUME_FILE}"
        return 0
    else
        log_error "Échec génération du résumé"
        return 1
    fi
}

# ============================================================================
# ÉTAPE 4 : Sauvegarde initiale
# ============================================================================

# --- create_initial_backup : Première sauvegarde de sécurité --------------
# Copie les fichiers critiques dans /var/backups/siem-africa/
create_initial_backup() {
    log_info "Création d'une sauvegarde initiale..."

    local backup_dir="/var/backups/siem-africa"
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_subdir="${backup_dir}/initial_${timestamp}"

    mkdir -p "$backup_subdir"

    # Fichiers à sauvegarder
    local files_to_backup=(
        "/etc/siem-africa/siem-africa.state.yaml"
        "/etc/siem-africa/RESUME.txt"
        "/etc/snort/snort.conf"
        "/etc/snort/snort.debian.conf"
        "/var/ossec/etc/ossec.conf"
    )

    local backup_count=0
    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            # Créer la structure de dossier dans le backup
            local relative_path
            relative_path=$(dirname "$file" | sed 's|^/||')
            mkdir -p "${backup_subdir}/${relative_path}"

            # Copier le fichier
            cp "$file" "${backup_subdir}/${relative_path}/" 2>/dev/null && \
                backup_count=$((backup_count + 1))
        fi
    done

    # Permissions sur le dossier de backup (lecture pour siem-africa uniquement)
    chown -R root:"${SIEM_GROUP}" "$backup_subdir" 2>/dev/null || true
    chmod -R 640 "$backup_subdir"/*
    find "$backup_subdir" -type d -exec chmod 750 {} \;

    log_success "Sauvegarde créée : ${backup_subdir} (${backup_count} fichiers)"

    # Nettoyage des vieilles sauvegardes (garder 7 dernières)
    cleanup_old_backups

    return 0
}

# --- cleanup_old_backups : Garde seulement les 7 dernières sauvegardes ----
cleanup_old_backups() {
    local backup_dir="/var/backups/siem-africa"
    local max_backups=7

    if [ ! -d "$backup_dir" ]; then
        return 0
    fi

    # Lister les backups triés par date (plus ancien en premier)
    # Et supprimer tout ce qui dépasse max_backups
    local backup_count
    backup_count=$(find "$backup_dir" -maxdepth 1 -type d -name "initial_*" | wc -l)

    if [ "$backup_count" -gt "$max_backups" ]; then
        local to_delete=$((backup_count - max_backups))
        log_info "Nettoyage : ${to_delete} ancienne(s) sauvegarde(s)..."

        find "$backup_dir" -maxdepth 1 -type d -name "initial_*" | \
            sort | \
            head -n "$to_delete" | \
            xargs -I {} rm -rf {}
    fi

    return 0
}

# ============================================================================
# ÉTAPE 5 : Copie du code source du module
# ============================================================================

# --- install_module_files : Copie les scripts dans /opt/siem-africa/ ------
# Pour que les futures mises à jour et la maintenance soient simples
install_module_files() {
    log_info "Installation des fichiers source du module..."

    local src_dir
    src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    local dest_dir="/opt/siem-africa/module-1"

    # Créer le dossier de destination si besoin
    mkdir -p "$dest_dir"

    # Copier l'ensemble du module
    # -r : récursif
    # -p : préserver les permissions
    if cp -rp "${src_dir}/"* "$dest_dir/" 2>/dev/null; then
        log_success "Fichiers copiés dans ${dest_dir}"
    else
        log_warning "Copie partielle dans ${dest_dir}"
    fi

    # Permissions
    chown -R root:"${SIEM_GROUP}" "$dest_dir"
    chmod -R g+rX "$dest_dir"

    # S'assurer que les scripts sont exécutables
    find "$dest_dir" -type f -name "*.sh" -exec chmod +x {} \;

    return 0
}

# ============================================================================
# ÉTAPE 6 : Tests de validation post-installation
# ============================================================================

# --- run_validation_tests : Exécute les tests finaux ----------------------
run_validation_tests() {
    log_info "Exécution des tests de validation..."

    local tests_passed=0
    local tests_failed=0

    # --- Test 1 : Services actifs ---
    if systemctl is-active --quiet snort; then
        log_success "Test service Snort : ACTIF ✓"
        tests_passed=$((tests_passed + 1))
    else
        log_error "Test service Snort : INACTIF ✗"
        tests_failed=$((tests_failed + 1))
    fi

    if systemctl is-active --quiet wazuh-manager; then
        log_success "Test service Wazuh Manager : ACTIF ✓"
        tests_passed=$((tests_passed + 1))
    else
        log_error "Test service Wazuh Manager : INACTIF ✗"
        tests_failed=$((tests_failed + 1))
    fi

    # Mode FULL : tester aussi Indexer et Dashboard
    if [ "$INSTALL_MODE" = "full" ]; then
        if systemctl is-active --quiet wazuh-indexer; then
            log_success "Test service Wazuh Indexer : ACTIF ✓"
            tests_passed=$((tests_passed + 1))
        else
            log_warning "Test service Wazuh Indexer : INACTIF (peut nécessiter plus de temps)"
        fi

        if systemctl is-active --quiet wazuh-dashboard; then
            log_success "Test service Wazuh Dashboard : ACTIF ✓"
            tests_passed=$((tests_passed + 1))
        else
            log_warning "Test service Wazuh Dashboard : INACTIF (peut nécessiter plus de temps)"
        fi
    fi

    # --- Test 2 : Fichiers critiques présents ---
    local critical_files=(
        "$STATE_FILE"
        "$RESUME_FILE"
        "/etc/snort/snort.conf"
        "/var/ossec/etc/ossec.conf"
    )

    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            log_success "Test fichier ${file} : EXISTE ✓"
            tests_passed=$((tests_passed + 1))
        else
            log_error "Test fichier ${file} : MANQUANT ✗"
            tests_failed=$((tests_failed + 1))
        fi
    done

    # --- Test 3 : Groupe siem-africa présent ---
    if group_exists "$SIEM_GROUP"; then
        log_success "Test groupe ${SIEM_GROUP} : EXISTE ✓"
        tests_passed=$((tests_passed + 1))
    else
        log_error "Test groupe ${SIEM_GROUP} : MANQUANT ✗"
        tests_failed=$((tests_failed + 1))
    fi

    # --- Test 4 : User siem-ids présent ---
    if user_exists "siem-ids"; then
        log_success "Test user siem-ids : EXISTE ✓"
        tests_passed=$((tests_passed + 1))
    else
        log_error "Test user siem-ids : MANQUANT ✗"
        tests_failed=$((tests_failed + 1))
    fi

    # --- Résumé des tests ---
    log_separator
    log_info "Résultat des tests : ${tests_passed} réussis, ${tests_failed} échoués"

    if [ "$tests_failed" -eq 0 ]; then
        log_success "Tous les tests de validation sont passés"
        return 0
    else
        log_warning "Certains tests ont échoué (voir détails ci-dessus)"
        return 1
    fi
}

# ============================================================================
# FONCTION PRINCIPALE DU MODULE
# ============================================================================

finalize_state() {
    local mode=$1

    log_info "Finalisation : génération du fichier d'état et tests..."

    # Vérifier que les fonctions sont disponibles
    check_state_functions || return 1

    # Générer les fichiers
    create_state_yaml "$mode"    || return 1
    create_resume_txt "$mode"    || return 1

    # Sauvegarde initiale
    create_initial_backup        || log_warning "Sauvegarde partielle"

    # Copier les sources
    install_module_files         || log_warning "Copie partielle des sources"

    # Tests de validation
    run_validation_tests         || log_warning "Certains tests ont échoué"

    log_success "Finalisation terminée"
    return 0
}

# ============================================================================
# Fin de modules/07-state-file.sh
# ============================================================================
