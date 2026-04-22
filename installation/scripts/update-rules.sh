#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# scripts/update-rules.sh — Téléchargement/mise à jour des règles Snort
# ============================================================================
#
# Ce script télécharge les règles Snort Community depuis Emerging Threats
# et les installe dans /etc/snort/rules/
#
# Utilisation :
#   sudo ./scripts/update-rules.sh          # Mise à jour manuelle
#   sudo ./scripts/update-rules.sh --force  # Force le téléchargement
#
# Exécution automatique :
#   Ce script est appelé :
#   1. Une fois à l'installation (par modules/02-snort.sh)
#   2. Chaque lundi à 3h du matin (via cron)
#
# Source utilisée : Emerging Threats Open (GRATUIT)
#   https://rules.emergingthreats.net/open/
#
# ============================================================================

# --- Chargement du contexte si appelé standalone ---------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -f "${SCRIPT_DIR}/core/logging.sh" ]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/core/logging.sh"
else
    # Fallback si appelé hors contexte
    log_info() { echo "[INFO] $*"; }
    log_success() { echo "[✓] $*"; }
    log_warning() { echo "[⚠] $*"; }
    log_error() { echo "[✗] $*" >&2; }
    die() { echo "[✗] $*" >&2; exit 1; }
fi

# --- Configuration --------------------------------------------------------
readonly ET_OPEN_URL="https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
readonly SNORT_RULES_DIR="/etc/snort/rules"
readonly SNORT_BACKUP_DIR="/var/backups/siem-africa/snort-rules"
readonly TEMP_DIR="/tmp/siem-africa-rules-update"
readonly CATEGORIES_FILE="${SCRIPT_DIR}/config/snort/enabled-categories.txt"

# ============================================================================
# FONCTION 1 : Vérification des prérequis
# ============================================================================

check_prerequisites() {
    # Root requis
    if [ "$(id -u)" -ne 0 ]; then
        die "Ce script doit être exécuté en tant que root"
    fi

    # Snort installé
    if ! command -v snort >/dev/null 2>&1; then
        die "Snort n'est pas installé. Lancez d'abord l'installation du Module 1."
    fi

    # Connexion internet
    if ! curl -s --head --fail --max-time 10 https://rules.emergingthreats.net >/dev/null 2>&1; then
        die "Impossible de joindre Emerging Threats. Vérifiez la connexion internet."
    fi

    # Outils requis
    for tool in curl tar wget; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            die "L'outil '${tool}' est requis mais non installé"
        fi
    done

    log_success "Prérequis OK"
    return 0
}

# ============================================================================
# FONCTION 2 : Sauvegarde des règles actuelles
# ============================================================================

backup_current_rules() {
    log_info "Sauvegarde des règles actuelles..."

    mkdir -p "$SNORT_BACKUP_DIR"

    if [ -d "$SNORT_RULES_DIR" ] && [ -n "$(ls -A "$SNORT_RULES_DIR" 2>/dev/null)" ]; then
        local backup_file
        backup_file="${SNORT_BACKUP_DIR}/rules-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

        tar czf "$backup_file" -C "$SNORT_RULES_DIR" . 2>/dev/null || true

        if [ -f "$backup_file" ]; then
            chmod 640 "$backup_file"
            log_success "Sauvegarde : ${backup_file}"

            # Rotation : garder les 5 dernières sauvegardes
            ls -t "${SNORT_BACKUP_DIR}"/rules-backup-*.tar.gz 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
        fi
    else
        log_info "Aucune règle existante à sauvegarder"
    fi

    return 0
}

# ============================================================================
# FONCTION 3 : Téléchargement des règles
# ============================================================================

download_rules() {
    log_info "Téléchargement des règles depuis Emerging Threats Open..."
    log_info "URL : ${ET_OPEN_URL}"

    # Nettoyer le dossier temporaire
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"

    local archive="${TEMP_DIR}/emerging.rules.tar.gz"

    # Téléchargement avec curl
    # --fail : échec si HTTP >= 400
    # --silent : pas de barre de progression
    # --show-error : mais afficher les erreurs
    # --max-time 300 : timeout 5 minutes (gros fichier ~30 MB)
    # --retry 3 : 3 tentatives
    if ! curl --fail --silent --show-error --max-time 300 --retry 3 \
              -o "$archive" "$ET_OPEN_URL" 2>&1 | tee -a "${LOG_FILE:-/dev/null}" >/dev/null; then
        log_error "Échec du téléchargement"
        log_info "Vérifiez :"
        log_info "  - Connexion internet : ping rules.emergingthreats.net"
        log_info "  - URL accessible : curl -I ${ET_OPEN_URL}"
        return 1
    fi

    # Vérification de la taille (doit faire au moins 10 MB)
    local size_mb
    size_mb=$(du -m "$archive" 2>/dev/null | cut -f1)

    if [ "$size_mb" -lt 10 ]; then
        log_error "Fichier téléchargé trop petit (${size_mb} MB), probablement corrompu"
        return 1
    fi

    log_success "Archive téléchargée : ${size_mb} MB"
    return 0
}

# ============================================================================
# FONCTION 4 : Extraction et filtrage des règles
# ============================================================================

extract_rules() {
    log_info "Extraction des règles..."

    local archive="${TEMP_DIR}/emerging.rules.tar.gz"

    # Extraction dans TEMP_DIR/rules/
    if ! tar xzf "$archive" -C "$TEMP_DIR" 2>&1 | tee -a "${LOG_FILE:-/dev/null}" >/dev/null; then
        log_error "Échec de l'extraction"
        return 1
    fi

    # ET livre les règles dans TEMP_DIR/rules/
    if [ ! -d "${TEMP_DIR}/rules" ]; then
        log_error "Dossier rules/ absent dans l'archive"
        return 1
    fi

    local rules_count
    rules_count=$(find "${TEMP_DIR}/rules" -name "*.rules" | wc -l)
    log_success "Extraction terminée : ${rules_count} fichiers de règles"

    return 0
}

# ============================================================================
# FONCTION 5 : Installation des règles (avec filtrage PME)
# ============================================================================

install_rules() {
    log_info "Installation des règles selon le profil PME..."

    # Lire la liste des catégories actives depuis le fichier de config
    local enabled_categories=()

    if [ -f "$CATEGORIES_FILE" ]; then
        # Lecture des lignes non vides et non commentées
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            [[ "$line" =~ ^# ]] && continue
            enabled_categories+=("$line")
        done < "$CATEGORIES_FILE"
        log_info "${#enabled_categories[@]} catégories activées (profil PME)"
    else
        log_warning "Fichier ${CATEGORIES_FILE} introuvable, activation par défaut"
        # Catégories par défaut si pas de fichier
        enabled_categories=(
            "scan.rules"
            "bruteforce.rules"
            "exploit.rules"
            "sql.rules"
            "trojan.rules"
            "dos.rules"
            "dns.rules"
            "web_server.rules"
            "mobile_malware.rules"
        )
    fi

    # S'assurer que le dossier cible existe
    mkdir -p "$SNORT_RULES_DIR"

    # Copie sélective : uniquement les catégories activées
    local copied=0
    local skipped=0

    for category in "${enabled_categories[@]}"; do
        local source_file="${TEMP_DIR}/rules/${category}"
        local target_file="${SNORT_RULES_DIR}/${category}"

        if [ -f "$source_file" ]; then
            # Préserver les fichiers custom (local.rules, white_list.rules, black_list.rules)
            if [ "$category" != "local.rules" ] && \
               [ "$category" != "white_list.rules" ] && \
               [ "$category" != "black_list.rules" ]; then
                cp "$source_file" "$target_file"
                copied=$((copied + 1))
            fi
        else
            # Certaines catégories peuvent avoir été renommées
            # On cherche des variantes
            local alternative
            alternative=$(find "${TEMP_DIR}/rules" -name "${category%.rules}*.rules" -type f 2>/dev/null | head -1)

            if [ -n "$alternative" ]; then
                cp "$alternative" "$target_file"
                copied=$((copied + 1))
            else
                skipped=$((skipped + 1))
                log_warning "Catégorie introuvable : ${category}"
            fi
        fi
    done

    # Copier aussi les fichiers support nécessaires (classification.config, reference.config, etc.)
    for support_file in classification.config reference.config; do
        if [ -f "${TEMP_DIR}/rules/${support_file}" ]; then
            cp "${TEMP_DIR}/rules/${support_file}" "${SNORT_RULES_DIR}/${support_file}"
        fi
    done

    # Permissions
    chown -R snort:snort "$SNORT_RULES_DIR" 2>/dev/null || \
        chown -R root:root "$SNORT_RULES_DIR"
    chmod -R 644 "$SNORT_RULES_DIR"/*.rules 2>/dev/null || true
    chmod 755 "$SNORT_RULES_DIR"

    log_success "Installation : ${copied} catégories activées, ${skipped} sautées"
    return 0
}

# ============================================================================
# FONCTION 6 : Génération du fichier snort.conf avec les includes
# ============================================================================

generate_snort_includes() {
    log_info "Génération des directives 'include' pour snort.conf..."

    local includes_file="/etc/snort/rules-includes.conf"

    # Début du fichier
    cat > "$includes_file" <<'EOF'
# ============================================================================
# SIEM AFRICA - Inclusions de règles
# ============================================================================
# Fichier généré automatiquement par update-rules.sh
# NE PAS MODIFIER MANUELLEMENT - sera écrasé au prochain update
# ============================================================================

EOF

    # Ajouter un include pour chaque fichier .rules présent
    local included=0
    for rules_file in "${SNORT_RULES_DIR}"/*.rules; do
        if [ -f "$rules_file" ]; then
            local basename
            basename=$(basename "$rules_file")
            echo "include \$RULE_PATH/${basename}" >> "$includes_file"
            included=$((included + 1))
        fi
    done

    # Ajouter le local.rules en dernier (priorité la plus haute)
    # Le fichier est vide par défaut mais l'admin peut y ajouter ses règles custom
    echo "" >> "$includes_file"
    echo "# Règles custom admin (priorité haute)" >> "$includes_file"
    echo "include \$RULE_PATH/local.rules" >> "$includes_file"

    log_success "${included} fichiers de règles inclus"
    log_info "Fichier include : ${includes_file}"

    return 0
}

# ============================================================================
# FONCTION 7 : Test de la config et reload
# ============================================================================

test_and_reload() {
    log_info "Test de la configuration Snort..."

    # Test parsing de la config
    if ! snort -T -c /etc/snort/snort.conf 2>&1 | grep -q "Snort successfully validated"; then
        log_warning "Configuration Snort a des avertissements"
        log_info "Voir : snort -T -c /etc/snort/snort.conf"
        # On ne fait pas échouer le script pour des warnings
    else
        log_success "Configuration Snort valide"
    fi

    # Reload du service
    if systemctl is-active --quiet snort.service 2>/dev/null; then
        log_info "Rechargement du service Snort..."
        if systemctl reload snort.service 2>/dev/null || systemctl restart snort.service; then
            log_success "Snort rechargé avec les nouvelles règles"
        else
            log_warning "Échec du reload, Snort utilise encore les anciennes règles"
            log_info "Solution : sudo systemctl restart snort"
        fi
    else
        log_info "Service Snort pas actif, sera démarré plus tard"
    fi

    return 0
}

# ============================================================================
# FONCTION 8 : Nettoyage
# ============================================================================

cleanup() {
    log_info "Nettoyage des fichiers temporaires..."
    rm -rf "$TEMP_DIR"
    log_success "Nettoyage terminé"
    return 0
}

# ============================================================================
# FONCTION 9 : Création du fichier local.rules vide (si inexistant)
# ============================================================================

ensure_local_rules() {
    local local_rules="${SNORT_RULES_DIR}/local.rules"

    if [ ! -f "$local_rules" ]; then
        cat > "$local_rules" <<'EOF'
# ============================================================================
# SIEM AFRICA - Règles locales Snort (custom admin)
# ============================================================================
# Ce fichier est destiné aux règles custom ajoutées par l'administrateur.
# Il n'est PAS écrasé par les mises à jour.
#
# Les règles principales sont gérées par Module 2 (base de données) qui
# contient le catalogue des attaques courantes avec mapping MITRE ATT&CK.
#
# Pour ajouter une règle manuelle :
#   alert tcp any any -> $HOME_NET 22 (msg:"Custom SSH alert"; sid:1000001;)
#
# ATTENTION : utilisez des SIDs >= 1000000 pour éviter conflits avec
# les règles communautaires.
# ============================================================================

EOF
        chmod 644 "$local_rules"
        chown snort:snort "$local_rules" 2>/dev/null || true
        log_info "Fichier local.rules vide créé : ${local_rules}"
    fi

    return 0
}

# ============================================================================
# FONCTION 10 : Création des listes vides
# ============================================================================

ensure_lists() {
    for list_name in white_list.rules black_list.rules; do
        local list_file="${SNORT_RULES_DIR}/${list_name}"

        if [ ! -f "$list_file" ]; then
            cat > "$list_file" <<EOF
# ============================================================================
# SIEM AFRICA - ${list_name}
# ============================================================================
# Une IP ou réseau CIDR par ligne
# ============================================================================

EOF
            chmod 644 "$list_file"
            chown snort:snort "$list_file" 2>/dev/null || true
        fi
    done

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

main() {
    log_info "========================================================"
    log_info "SIEM AFRICA - Mise à jour des règles Snort"
    log_info "Source : Emerging Threats Open (gratuit)"
    log_info "========================================================"

    check_prerequisites     || exit 1
    backup_current_rules    || log_warning "Backup échoué (non bloquant)"
    download_rules          || die "Échec du téléchargement"
    extract_rules           || die "Échec de l'extraction"
    install_rules           || die "Échec de l'installation"
    ensure_local_rules      # non bloquant
    ensure_lists            # non bloquant
    generate_snort_includes || die "Échec de la génération des includes"
    test_and_reload         # non bloquant
    cleanup                 # non bloquant

    log_success "Mise à jour terminée ✓"
    log_info "Nombre total de règles actives :"
    local total_rules
    total_rules=$(cat "$SNORT_RULES_DIR"/*.rules 2>/dev/null | grep -c "^alert" || echo "0")
    log_info "  ${total_rules} règles"

    return 0
}

# Lancement
main "$@"
