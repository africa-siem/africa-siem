#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# core/users.sh — Gestion du groupe et des utilisateurs système
# ============================================================================
#
# Ce fichier gère la création du groupe siem-africa et des utilisateurs
# système pour chaque module.
#
# ARCHITECTURE DES USERS :
#
#   Groupe principal : siem-africa
#     │
#     ├── siem-ids    → Module 1 (Snort + Wazuh Manager)
#     ├── siem-db     → Module 2 (Base de données SQLite)
#     ├── siem-agent  → Module 3 (Agent Python + iptables)
#     └── siem-web    → Module 4 (Dashboard Django)
#
#   User admin humain : ajouté au groupe siem-africa via usermod
#
# PRINCIPE DE SÉCURITÉ :
#   - Users service : shell /bin/false (pas de connexion directe)
#   - Pas de home directory (sécurité max)
#   - Appartenance au groupe pour accès fichiers partagés
#
# ============================================================================

# --- Nom du groupe principal ----------------------------------------------
readonly SIEM_GROUP="siem-africa"

# --- Dictionnaire des users par module ------------------------------------
# Format : "nom_user:description"
declare -A SIEM_USERS=(
    ["siem-ids"]="Module 1 - Snort IDS et Wazuh Manager"
    ["siem-db"]="Module 2 - Base de données SQLite"
    ["siem-agent"]="Module 3 - Agent Python intelligent"
    ["siem-web"]="Module 4 - Dashboard Django"
)

# ============================================================================
# GESTION DU GROUPE
# ============================================================================

# --- create_siem_group : Crée le groupe siem-africa -----------------------
# Idempotent : si le groupe existe déjà, ne fait rien (pas d'erreur).
# Retour : 0 si OK, 1 si erreur
create_siem_group() {
    # getent group : interrogeur standard pour vérifier l'existence d'un groupe
    # Redirige stdout vers /dev/null car on veut juste le code retour
    if getent group "$SIEM_GROUP" >/dev/null 2>&1; then
        log_info "Groupe '${SIEM_GROUP}' existe déjà"
        return 0
    fi

    # groupadd : commande standard de création de groupe
    # -r : groupe "système" (GID < 1000 généralement)
    if groupadd -r "$SIEM_GROUP" 2>/dev/null; then
        local gid
        gid=$(getent group "$SIEM_GROUP" | cut -d: -f3)
        log_success "Groupe '${SIEM_GROUP}' créé (GID: ${gid})"
        return 0
    else
        log_error "Échec création du groupe '${SIEM_GROUP}'"
        return 1
    fi
}

# --- group_exists : Retourne 0 si le groupe existe ------------------------
group_exists() {
    local group=$1
    getent group "$group" >/dev/null 2>&1
}

# ============================================================================
# GESTION DES USERS SERVICE
# ============================================================================

# --- create_siem_user : Crée un utilisateur système pour un module --------
#
# Arguments :
#   $1 : nom du user (ex: "siem-ids")
#   $2 : description (ex: "Module 1 - Snort + Wazuh")
#
# Caractéristiques du user créé :
#   - user système (UID < 1000)
#   - shell /bin/false (pas de connexion)
#   - pas de home directory
#   - membre du groupe siem-africa
#
# Retour : 0 si OK, 1 si erreur
create_siem_user() {
    local username=$1
    local description=$2

    # Vérification que le groupe existe d'abord
    if ! group_exists "$SIEM_GROUP"; then
        log_error "Le groupe '${SIEM_GROUP}' doit exister avant de créer '${username}'"
        log_info  "Appelez create_siem_group() d'abord"
        return 1
    fi

    # Vérification si le user existe déjà
    if id "$username" >/dev/null 2>&1; then
        log_info "User '${username}' existe déjà"

        # S'assurer qu'il est bien dans le groupe siem-africa
        if ! groups "$username" 2>/dev/null | grep -q "\b${SIEM_GROUP}\b"; then
            usermod -aG "$SIEM_GROUP" "$username"
            log_info "User '${username}' ajouté au groupe '${SIEM_GROUP}'"
        fi

        return 0
    fi

    # Création du user avec les paramètres de sécurité
    # -r : user système
    # -s /bin/false : pas de shell (impossible de se connecter)
    # -M : pas de home directory
    # -g : groupe primaire
    # -c : commentaire (description)
    if useradd -r -s /bin/false -M -g "$SIEM_GROUP" -c "$description" "$username" 2>/dev/null; then
        local uid
        uid=$(id -u "$username")
        log_success "User '${username}' créé (UID: ${uid}, groupe: ${SIEM_GROUP})"
        return 0
    else
        log_error "Échec création du user '${username}'"
        return 1
    fi
}

# --- user_exists : Retourne 0 si le user existe ---------------------------
user_exists() {
    local username=$1
    id "$username" >/dev/null 2>&1
}

# ============================================================================
# AJOUT DE L'ADMIN HUMAIN AU GROUPE
# ============================================================================

# --- add_admin_to_group : Ajoute l'utilisateur humain au groupe -----------
# Détecte l'utilisateur qui a lancé sudo et l'ajoute au groupe siem-africa.
# Cela permet à l'admin humain d'accéder aux fichiers du SIEM sans être root.
add_admin_to_group() {
    # SUDO_USER est défini quand le script est lancé via sudo
    # Sinon on essaie logname (l'utilisateur de la session originale)
    local admin_user="${SUDO_USER:-$(logname 2>/dev/null)}"

    if [ -z "$admin_user" ] || [ "$admin_user" = "root" ]; then
        log_warning "Impossible de détecter l'utilisateur admin humain"
        log_info  "Ajoutez manuellement un user au groupe : sudo usermod -aG ${SIEM_GROUP} <votre_user>"
        return 1
    fi

    # Vérifier que le user existe
    if ! user_exists "$admin_user"; then
        log_warning "User '${admin_user}' introuvable, ajout manuel nécessaire"
        return 1
    fi

    # Ajouter au groupe siem-africa (en plus de ses groupes existants)
    # -a : append (ajouter, ne pas remplacer)
    # -G : groupes supplémentaires
    if usermod -aG "$SIEM_GROUP" "$admin_user" 2>/dev/null; then
        log_success "Admin '${admin_user}' ajouté au groupe '${SIEM_GROUP}'"
        log_info  "⚠️  L'admin doit se reconnecter pour que le changement soit effectif"
        return 0
    else
        log_error "Échec ajout de '${admin_user}' au groupe '${SIEM_GROUP}'"
        return 1
    fi
}

# ============================================================================
# CRÉATION DES RÉPERTOIRES AVEC PERMISSIONS
# ============================================================================

# --- create_siem_directories : Crée l'arborescence de dossiers ------------
# Crée les dossiers standards de SIEM Africa avec les bonnes permissions :
#
#   /etc/siem-africa/          (config globale)
#   /etc/siem-africa/secrets/  (secrets - permissions strictes)
#   /var/lib/siem-africa/      (données partagées)
#   /var/log/siem-africa/      (logs)
#   /opt/siem-africa/          (code des modules)
#   /var/backups/siem-africa/  (sauvegardes)
create_siem_directories() {
    # Le groupe doit exister
    if ! group_exists "$SIEM_GROUP"; then
        log_error "Le groupe '${SIEM_GROUP}' doit exister avant de créer les dossiers"
        return 1
    fi

    # Configuration globale
    # Permissions : root:siem-africa, 750 (lecture/exécution pour le groupe)
    mkdir -p /etc/siem-africa
    chown root:"$SIEM_GROUP" /etc/siem-africa
    chmod 750 /etc/siem-africa
    log_success "Dossier /etc/siem-africa créé (750)"

    # Secrets (permissions ultra-strictes : 700, seul root)
    mkdir -p /etc/siem-africa/secrets
    chown root:root /etc/siem-africa/secrets
    chmod 700 /etc/siem-africa/secrets
    log_success "Dossier /etc/siem-africa/secrets créé (700)"

    # Données partagées entre modules
    # Permissions : 775 (lecture/écriture pour le groupe)
    mkdir -p /var/lib/siem-africa
    chown root:"$SIEM_GROUP" /var/lib/siem-africa
    chmod 775 /var/lib/siem-africa
    log_success "Dossier /var/lib/siem-africa créé (775)"

    # Logs
    # Permissions : 775 pour que tous les users service puissent écrire
    mkdir -p /var/log/siem-africa
    chown root:"$SIEM_GROUP" /var/log/siem-africa
    chmod 775 /var/log/siem-africa
    log_success "Dossier /var/log/siem-africa créé (775)"

    # Code des modules (installation)
    mkdir -p /opt/siem-africa
    chown root:"$SIEM_GROUP" /opt/siem-africa
    chmod 755 /opt/siem-africa
    log_success "Dossier /opt/siem-africa créé (755)"

    # Sauvegardes
    mkdir -p /var/backups/siem-africa
    chown root:"$SIEM_GROUP" /var/backups/siem-africa
    chmod 770 /var/backups/siem-africa
    log_success "Dossier /var/backups/siem-africa créé (770)"

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE : Setup complet utilisateurs pour Module 1
# ============================================================================

# --- setup_module1_users : Installe le groupe + user Module 1 ------------
# Fonction appelée par le script d'installation principal du Module 1.
#
# Effectue dans l'ordre :
#   1. Création du groupe siem-africa
#   2. Création du user siem-ids (Module 1)
#   3. Ajout de l'admin humain au groupe
#   4. Création des répertoires avec permissions
setup_module1_users() {
    log_info "Configuration des utilisateurs et groupes..."

    # Étape 1 : groupe principal
    create_siem_group || die "Impossible de créer le groupe ${SIEM_GROUP}"

    # Étape 2 : user du Module 1
    create_siem_user "siem-ids" "${SIEM_USERS[siem-ids]}" \
        || die "Impossible de créer le user siem-ids"

    # Étape 3 : admin humain
    add_admin_to_group  # non bloquant

    # Étape 4 : dossiers
    create_siem_directories || die "Impossible de créer les dossiers"

    log_success "Configuration des utilisateurs terminée"
    return 0
}

# ============================================================================
# FONCTIONS DE NETTOYAGE (utilisées par uninstall.sh)
# ============================================================================

# --- remove_siem_user : Supprime un user système --------------------------
# Argument : $1 = nom du user (ex: "siem-ids")
remove_siem_user() {
    local username=$1

    if ! user_exists "$username"; then
        log_info "User '${username}' n'existe pas, rien à faire"
        return 0
    fi

    if userdel "$username" 2>/dev/null; then
        log_success "User '${username}' supprimé"
        return 0
    else
        log_error "Échec suppression du user '${username}'"
        return 1
    fi
}

# --- remove_siem_group : Supprime le groupe siem-africa -------------------
# À n'appeler qu'après avoir supprimé tous les users du groupe.
remove_siem_group() {
    if ! group_exists "$SIEM_GROUP"; then
        log_info "Groupe '${SIEM_GROUP}' n'existe pas"
        return 0
    fi

    # Vérifier qu'aucun user n'est encore dans le groupe
    local remaining_users
    remaining_users=$(getent group "$SIEM_GROUP" | cut -d: -f4)

    if [ -n "$remaining_users" ]; then
        log_warning "Des users sont encore dans le groupe : ${remaining_users}"
        log_info  "Supprimez-les d'abord ou retirez-les du groupe"
        return 1
    fi

    if groupdel "$SIEM_GROUP" 2>/dev/null; then
        log_success "Groupe '${SIEM_GROUP}' supprimé"
        return 0
    else
        log_error "Échec suppression du groupe '${SIEM_GROUP}'"
        return 1
    fi
}

# ============================================================================
# Fin de core/users.sh
# ============================================================================
