#!/bin/bash
# ============================================================================
# PATCH AUTO-CLEANUP — À ajouter au DÉBUT de chaque modules/XX-*.sh
# ============================================================================
#
# INSTRUCTIONS D'INTÉGRATION
# ---------------------------
#
# 1. Ouvrir chaque fichier modules/XX-*.sh
# 2. Juste après le "source" des fichiers core/ (logging.sh, langue.sh, etc.)
#    AJOUTER la ligne :
#
#       source "${SCRIPT_DIR}/core/cleanup.sh"
#
# 3. Puis dans la fonction principale du module, AVANT l'installation,
#    AJOUTER l'appel à cleanup_XXX selon le module :
#
#    ┌───────────────────────────────────────────────┬──────────────────────┐
#    │ Module                                        │ Appel à ajouter      │
#    ├───────────────────────────────────────────────┼──────────────────────┤
#    │ modules/02-snort.sh                           │ cleanup_snort        │
#    │ modules/03-wazuh-manager.sh                   │ cleanup_wazuh_manager│
#    │                                               │ cleanup_filebeat     │
#    │ modules/04-wazuh-indexer.sh                   │ cleanup_wazuh_indexer│
#    │ modules/05-wazuh-dashboard.sh                 │ cleanup_wazuh_dashboard│
#    └───────────────────────────────────────────────┴──────────────────────┘
#
# EXEMPLE CONCRET — modules/02-snort.sh
# --------------------------------------
#
# AVANT (début du fichier) :
#
#   #!/bin/bash
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
#   source "${SCRIPT_DIR}/core/logging.sh"
#   source "${SCRIPT_DIR}/core/langue.sh"
#
#   install_snort() {
#       log_step "5/8" "Installation Snort"
#       apt-get install -y snort
#       ...
#   }
#
# APRÈS (avec le patch) :
#
#   #!/bin/bash
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
#   source "${SCRIPT_DIR}/core/logging.sh"
#   source "${SCRIPT_DIR}/core/langue.sh"
#   source "${SCRIPT_DIR}/core/cleanup.sh"   # ← AJOUT
#
#   install_snort() {
#       log_step "5/8" "Installation Snort"
#
#       # ← AJOUT : détection + nettoyage avant installation
#       cleanup_snort
#
#       apt-get install -y snort
#       ...
#   }
#
# ============================================================================

# ============================================================================
# PATCHES AUTOMATIQUES PAR MODULE
# ============================================================================
# Voici les lignes exactes à ajouter à chaque fichier.
# Copie-colle-les dans les bons fichiers selon le tableau ci-dessus.
# ============================================================================

# --- modules/02-snort.sh ---------------------------------------------------
# Ligne 1 à ajouter après les "source core/" :
#     source "${SCRIPT_DIR}/core/cleanup.sh"
#
# Ligne 2 à ajouter en première instruction de la fonction d'install principale :
#     cleanup_snort

# --- modules/03-wazuh-manager.sh -------------------------------------------
# Source :
#     source "${SCRIPT_DIR}/core/cleanup.sh"
#
# En début de fonction d'install :
#     cleanup_wazuh_manager
#     cleanup_filebeat
#     # Note : on NE purge PAS le dépôt APT Wazuh car on en a besoin pour réinstaller

# --- modules/04-wazuh-indexer.sh -------------------------------------------
# Source :
#     source "${SCRIPT_DIR}/core/cleanup.sh"
#
# En début de fonction d'install :
#     cleanup_wazuh_indexer

# --- modules/05-wazuh-dashboard.sh -----------------------------------------
# Source :
#     source "${SCRIPT_DIR}/core/cleanup.sh"
#
# En début de fonction d'install :
#     cleanup_wazuh_dashboard

# --- modules/01-system-prep.sh ---------------------------------------------
# PAS DE cleanup nécessaire ici — ce module crée juste le groupe + users
# (les fonctions create_siem_group et create_siem_user sont déjà idempotentes)

# --- modules/06-integration.sh ---------------------------------------------
# PAS DE cleanup dédié — ce module configure l'intégration Snort↔Wazuh
# Il s'exécute APRÈS les installs individuelles, donc rien à purger

# --- modules/07-state-file.sh ----------------------------------------------
# PAS DE cleanup — ce module génère le fichier d'état à la fin
# Si on veut reset, on utilise cleanup_siem_state_files depuis clean-install.sh
