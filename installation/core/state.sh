#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# core/state.sh — Gestion du fichier d'état YAML
# ============================================================================
#
# Ce fichier gère la création et la mise à jour du fichier d'état central
# de SIEM Africa. Ce fichier documente en détail l'état du système.
#
# Fichiers générés :
#   /etc/siem-africa/siem-africa.state.yaml   (format structuré YAML)
#   /etc/siem-africa/RESUME.txt               (format lisible humain)
#
# Permissions :
#   - state.yaml : 640 (root:siem-africa) — lecture pour admins
#   - RESUME.txt : 640 (root:siem-africa) — lecture pour admins
#
# ============================================================================

# --- Chemins standardisés -------------------------------------------------
readonly STATE_FILE="/etc/siem-africa/siem-africa.state.yaml"
readonly RESUME_FILE="/etc/siem-africa/RESUME.txt"
readonly SECRETS_DIR="/etc/siem-africa/secrets"

# ============================================================================
# GÉNÉRATION DU FICHIER D'ÉTAT YAML
# ============================================================================

# --- generate_state_file : Crée le fichier state.yaml initial -------------
# Argument : $1 = mode d'installation ("lite" ou "full")
#
# Ce fichier est créé à la fin de l'installation du Module 1.
# Les modules suivants (2, 3, 4) le mettront à jour.
generate_state_file() {
    local mode=$1
    local install_date
    install_date=$(date '+%Y-%m-%d %H:%M:%S')

    # Récupération des infos système
    local hostname_val
    hostname_val=$(hostname)

    # On crée le fichier avec un "here-document" (syntaxe bash pour bloc de texte)
    cat > "$STATE_FILE" <<EOF
# =====================================================
# SIEM AFRICA - Fichier d'état de l'installation
# =====================================================
# Fichier généré automatiquement par le Module 1.
# Ne pas modifier manuellement.
# Dernière mise à jour : ${install_date}
# =====================================================

installation:
  date: "${install_date}"
  mode: "${mode}"
  langue: "${SIEM_LANG:-fr}"
  version_siem_africa: "2.0"
  derniere_maj: "${install_date}"

systeme:
  hostname: "${hostname_val}"
  ip_principale: "${DETECTED_IP:-inconnu}"
  interface_monitoring: "${DETECTED_INTERFACE:-inconnu}"
$(get_os_info_yaml)

groupe_et_users:
  groupe_principal:
    nom: "${SIEM_GROUP}"
    gid: "$(getent group "${SIEM_GROUP}" | cut -d: -f3)"
    date_creation: "${install_date}"

  users_crees:
    - nom: "siem-ids"
      module: 1
      description: "Module 1 - Snort IDS et Wazuh Manager"
      uid: "$(id -u siem-ids 2>/dev/null || echo 'n/a')"
      shell: "/bin/false"
      home: "aucun"
      date_creation: "${install_date}"

modules:
  module_1:
    statut: "installé"
    date_installation: "${install_date}"
    version: "2.0"
    mode: "${mode}"

    composants:
      snort:
        version: "2.9.x"
        config_file: "/etc/snort/snort.conf"
        log_dir: "/var/log/snort/"
        interface_monitoring: "${DETECTED_INTERFACE:-inconnu}"
        mode_detection: "IDS passif"
        service_name: "snort.service"

      wazuh_manager:
        version: "4.14"
        config_file: "/var/ossec/etc/ossec.conf"
        alerts_file: "/var/ossec/logs/alerts/alerts.json"
        service_name: "wazuh-manager.service"
        port_agents: 1514
        port_enrollment: 1515
        port_api: 55000
EOF

    # Ajout des composants full uniquement si mode=full
    if [ "$mode" = "full" ]; then
        cat >> "$STATE_FILE" <<EOF

      wazuh_indexer:
        version: "4.14"
        port: 9200
        service_name: "wazuh-indexer.service"
        data_dir: "/var/lib/wazuh-indexer/"

      wazuh_dashboard:
        version: "4.14"
        url: "https://${DETECTED_IP:-inconnu}"
        port: 443
        service_name: "wazuh-dashboard.service"
        admin_user: "admin"
        admin_password_file: "${SECRETS_DIR}/wazuh-admin.pwd"
EOF
    fi

    # Suite : modules non encore installés + commandes utiles
    cat >> "$STATE_FILE" <<EOF

  module_2:
    statut: "non_installé"
    description: "Base de données SQLite + 380 signatures MITRE"

  module_3:
    statut: "non_installé"
    description: "Agent Python intelligent (corrélation, honeypots, iptables)"

  module_4:
    statut: "non_installé"
    description: "Dashboard web Django"

commandes_utiles:
  module_1:
    verifier_snort: "sudo systemctl status snort"
    verifier_wazuh_manager: "sudo systemctl status wazuh-manager"
EOF

    if [ "$mode" = "full" ]; then
        cat >> "$STATE_FILE" <<EOF
    verifier_wazuh_indexer: "sudo systemctl status wazuh-indexer"
    verifier_wazuh_dashboard: "sudo systemctl status wazuh-dashboard"
    redemarrer_tout: "sudo systemctl restart snort wazuh-manager wazuh-indexer wazuh-dashboard"
EOF
    else
        cat >> "$STATE_FILE" <<EOF
    redemarrer_tout: "sudo systemctl restart snort wazuh-manager"
EOF
    fi

    cat >> "$STATE_FILE" <<EOF
    voir_logs_snort: "sudo tail -f /var/log/snort/alert"
    voir_logs_wazuh: "sudo tail -f /var/ossec/logs/alerts/alerts.json"
    tester_integration: "sudo /opt/siem-africa/module-1/tests/test-integration.sh"

  global:
    voir_status_complet: "sudo cat ${STATE_FILE}"
    voir_resume: "sudo cat ${RESUME_FILE}"
    voir_log_installation: "sudo cat /var/log/siem-africa/install.log"

chemins_importants:
  installation: "/opt/siem-africa/"
  configuration: "/etc/siem-africa/"
  donnees: "/var/lib/siem-africa/"
  logs: "/var/log/siem-africa/"
  fichier_etat: "${STATE_FILE}"
  fichier_resume: "${RESUME_FILE}"
  secrets: "${SECRETS_DIR}"
  backups: "/var/backups/siem-africa/"

ports_utilises:
  - port: 22
    service: "SSH"
    usage: "Administration système"
  - port: 1514
    service: "Wazuh Manager"
    usage: "Communication avec les agents (TCP/UDP)"
  - port: 1515
    service: "Wazuh Manager"
    usage: "Enrôlement des agents (TCP)"
  - port: 55000
    service: "Wazuh API"
    usage: "Gestion via API"
EOF

    if [ "$mode" = "full" ]; then
        cat >> "$STATE_FILE" <<EOF
  - port: 9200
    service: "Wazuh Indexer"
    usage: "Stockage données (OpenSearch)"
  - port: 443
    service: "Wazuh Dashboard"
    usage: "Interface web HTTPS"
EOF
    fi

    cat >> "$STATE_FILE" <<EOF

sauvegardes:
  repertoire: "/var/backups/siem-africa/"
  rotation: "7 jours"
  frequence: "manuelle (V2.0) - automatique prévue en V2.1"

support:
  projet: "SIEM Africa"
  repo: "github.com/africa-siem/africa-siem"
  documentation: "/opt/siem-africa/module-1/README.md"
  faq: "/opt/siem-africa/module-1/FAQ-JURY.md"
EOF

    # Application des permissions strictes
    chown root:"${SIEM_GROUP}" "$STATE_FILE"
    chmod 640 "$STATE_FILE"

    log_success "Fichier d'état créé : ${STATE_FILE}"
    return 0
}

# ============================================================================
# GÉNÉRATION DU RESUME.TXT LISIBLE
# ============================================================================

# --- generate_resume_file : Crée le résumé humain -------------------------
# Argument : $1 = mode d'installation ("lite" ou "full")
#
# Ce fichier est conçu pour être lu par l'admin. Il contient :
#   - État du système
#   - Credentials (mot de passe Wazuh Dashboard si mode full)
#   - Commandes utiles
#   - Chemins importants
#   - Prochaines étapes
generate_resume_file() {
    local mode=$1
    local install_date
    install_date=$(date '+%d %B %Y à %H:%M')

    # En-tête commune
    cat > "$RESUME_FILE" <<EOF
╔═══════════════════════════════════════════════════════╗
║           SIEM AFRICA - RÉSUMÉ INSTALLATION           ║
╚═══════════════════════════════════════════════════════╝

📅 Installé le : ${install_date}
🏷️  Mode       : ${mode^^}
🌐 IP serveur  : ${DETECTED_IP:-à configurer}
🔌 Interface   : ${DETECTED_INTERFACE:-à configurer}
💻 Système     : ${OS_NAME:-Linux} ${OS_VERSION:-?}

═══════════════════════════════════════════════════════

📊 MODULES INSTALLÉS
───────────────────────────────────────────────────────
  ✅ Module 1 - IDS & SIEM (Snort + Wazuh)
  ⏳ Module 2 - Base de données (à installer)
  ⏳ Module 3 - Agent Python (à installer)
  ⏳ Module 4 - Dashboard web (à installer)

═══════════════════════════════════════════════════════

EOF

    # Credentials (uniquement si mode=full avec dashboard)
    if [ "$mode" = "full" ]; then
        cat >> "$RESUME_FILE" <<EOF
🔐 IDENTIFIANTS WAZUH DASHBOARD
───────────────────────────────────────────────────────
  URL          : https://${DETECTED_IP:-<IP_SERVEUR>}
  Utilisateur  : admin
  Mot de passe : [voir ${SECRETS_DIR}/wazuh-admin.pwd]

  Pour afficher le mot de passe :
  sudo cat ${SECRETS_DIR}/wazuh-admin.pwd

  ⚠️  IMPORTANT :
  - CHANGEZ ce mot de passe dès la première connexion
  - NE PARTAGEZ JAMAIS ce fichier
  - Le certificat HTTPS est auto-signé (normal en V2.0)

═══════════════════════════════════════════════════════

EOF
    fi

    # Commandes utiles
    cat >> "$RESUME_FILE" <<EOF
🔧 COMMANDES DE VÉRIFICATION
───────────────────────────────────────────────────────

  📌 Vérifier que Snort fonctionne :
     sudo systemctl status snort

  📌 Vérifier que Wazuh Manager fonctionne :
     sudo systemctl status wazuh-manager
EOF

    if [ "$mode" = "full" ]; then
        cat >> "$RESUME_FILE" <<EOF

  📌 Vérifier que Wazuh Indexer fonctionne :
     sudo systemctl status wazuh-indexer

  📌 Vérifier que Wazuh Dashboard fonctionne :
     sudo systemctl status wazuh-dashboard
EOF
    fi

    cat >> "$RESUME_FILE" <<EOF

  📌 Voir les alertes en temps réel :
     sudo tail -f /var/ossec/logs/alerts/alerts.json

  📌 Voir les logs Snort :
     sudo tail -f /var/log/snort/alert

  📌 Redémarrer tous les services :
EOF

    if [ "$mode" = "full" ]; then
        echo "     sudo systemctl restart snort wazuh-manager wazuh-indexer wazuh-dashboard" >> "$RESUME_FILE"
    else
        echo "     sudo systemctl restart snort wazuh-manager" >> "$RESUME_FILE"
    fi

    # Chemins importants
    cat >> "$RESUME_FILE" <<EOF

  📌 Tester l'intégration complète :
     sudo /opt/siem-africa/module-1/tests/test-integration.sh

═══════════════════════════════════════════════════════

📁 EMPLACEMENTS IMPORTANTS
───────────────────────────────────────────────────────
  Config Snort        : /etc/snort/snort.conf
  Config Wazuh        : /var/ossec/etc/ossec.conf
  Alertes JSON        : /var/ossec/logs/alerts/alerts.json
  Logs installation   : /var/log/siem-africa/install.log
  Fichier d'état      : ${STATE_FILE}
  Fichier résumé      : ${RESUME_FILE}
  Secrets             : ${SECRETS_DIR}/
  Sauvegardes         : /var/backups/siem-africa/

═══════════════════════════════════════════════════════

👥 UTILISATEURS SYSTÈME CRÉÉS
───────────────────────────────────────────────────────
  Groupe principal    : ${SIEM_GROUP}
  User Module 1       : siem-ids (shell: /bin/false)

  Prochains modules créeront :
  - siem-db    (Module 2)
  - siem-agent (Module 3)
  - siem-web   (Module 4)

═══════════════════════════════════════════════════════

🚀 PROCHAINE ÉTAPE
───────────────────────────────────────────────────────
  Installer le Module 2 (base de données) :

    cd /opt/siem-africa/module-2-database
    sudo ./install.sh

═══════════════════════════════════════════════════════

📞 AIDE & DOCUMENTATION
───────────────────────────────────────────────────────
  Documentation complète : /opt/siem-africa/module-1/README.md
  Guide installation     : /opt/siem-africa/module-1/INSTALL.md
  FAQ soutenance         : /opt/siem-africa/module-1/FAQ-JURY.md
  Logs détaillés         : /var/log/siem-africa/install.log

═══════════════════════════════════════════════════════

🛠️  DÉPANNAGE RAPIDE
───────────────────────────────────────────────────────
  • Snort ne démarre pas   → sudo journalctl -u snort -n 50
  • Wazuh ne démarre pas   → sudo journalctl -u wazuh-manager -n 50
  • Réparer l'installation → sudo /opt/siem-africa/module-1/repair.sh
  • Désinstaller tout      → sudo /opt/siem-africa/module-1/uninstall.sh

═══════════════════════════════════════════════════════

*SIEM Africa v2.0 — IUT de Douala — ${install_date}*
EOF

    # Permissions
    chown root:"${SIEM_GROUP}" "$RESUME_FILE"
    chmod 640 "$RESUME_FILE"

    log_success "Résumé créé : ${RESUME_FILE}"
    return 0
}

# ============================================================================
# MISE À JOUR DU FICHIER D'ÉTAT (pour futurs modules)
# ============================================================================

# --- update_state_module : Met à jour le statut d'un module ---------------
# Utilisé par les futurs modules (2, 3, 4) pour s'enregistrer.
#
# Arguments :
#   $1 : numéro du module (ex: "2")
#   $2 : statut ("installé", "désinstallé", etc.)
#
# Pour l'instant, cette fonction log juste. Une vraie édition YAML sera
# implémentée avec Python/yq dans les modules suivants.
update_state_module() {
    local module_num=$1
    local statut=$2

    if [ ! -f "$STATE_FILE" ]; then
        log_warning "Fichier d'état inexistant, impossible de mettre à jour"
        return 1
    fi

    log_info "Mise à jour état : module_${module_num} → ${statut}"
    # TODO V2.1 : éditer le YAML avec 'yq' ou Python PyYAML
    # Pour l'instant, chaque module régénère le fichier complet

    return 0
}

# ============================================================================
# AFFICHAGE DU RESUME À LA FIN DE L'INSTALLATION
# ============================================================================

# --- display_resume : Affiche le RESUME.txt à la fin ----------------------
# Appelé automatiquement à la fin de l'installation réussie.
display_resume() {
    if [ -f "$RESUME_FILE" ]; then
        echo ""
        cat "$RESUME_FILE"
        echo ""
    else
        log_warning "Fichier RESUME.txt introuvable"
    fi
}

# ============================================================================
# GESTION DES SECRETS
# ============================================================================

# --- save_secret : Sauvegarde un secret dans un fichier dédié -------------
# Arguments :
#   $1 : nom du secret (ex: "wazuh-admin.pwd")
#   $2 : valeur du secret
save_secret() {
    local name=$1
    local value=$2
    local filepath="${SECRETS_DIR}/${name}"

    # S'assurer que le dossier secrets existe avec bonnes permissions
    if [ ! -d "$SECRETS_DIR" ]; then
        mkdir -p "$SECRETS_DIR"
        chown root:root "$SECRETS_DIR"
        chmod 700 "$SECRETS_DIR"
    fi

    # Écrire le secret avec permissions ultra-strictes
    echo -n "$value" > "$filepath"
    chown root:root "$filepath"
    chmod 600 "$filepath"

    log_success "Secret sauvegardé : ${filepath} (permissions 600)"
}

# --- get_secret : Lit un secret (nécessite droits root) -------------------
get_secret() {
    local name=$1
    local filepath="${SECRETS_DIR}/${name}"

    if [ -f "$filepath" ]; then
        cat "$filepath"
    else
        log_error "Secret introuvable : ${filepath}"
        return 1
    fi
}

# ============================================================================
# Fin de core/state.sh
# ============================================================================
