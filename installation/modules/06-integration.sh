#!/bin/bash
# ============================================================================
# SIEM AFRICA — Module 1
# modules/06-integration.sh — Intégration Snort ↔ Wazuh
# ============================================================================
#
# Ce module connecte Snort à Wazuh pour que les alertes Snort soient
# traitées par le SIEM.
#
# Principe :
#   1. Snort écrit ses alertes dans /var/log/snort/alert (format "fast")
#   2. On configure Wazuh pour lire ce fichier
#   3. Wazuh applique ses décodeurs et règles
#   4. Les alertes enrichies sont écrites dans /var/ossec/logs/alerts/alerts.json
#
# Decodeur Wazuh natif :
#   Wazuh 4.x inclut nativement un decoder "snort-fast" qui parse le format
#   "fast" de Snort. Il suffit de pointer Wazuh vers le bon fichier.
#
# ============================================================================

# ============================================================================
# ÉTAPE 1 : Configuration de Wazuh pour lire les logs Snort
# ============================================================================

configure_wazuh_localfile_snort() {
    log_info "Configuration de Wazuh pour lire les alertes Snort..."

    local ossec_conf="/var/ossec/etc/ossec.conf"
    local snort_log="/var/log/snort/alert"

    if [ ! -f "$ossec_conf" ]; then
        log_error "ossec.conf introuvable"
        return 1
    fi

    # On ne modifie PAS directement ossec.conf (fichier géré par Wazuh)
    # On utilise le mécanisme des fichiers locaux : local_*.xml
    #
    # Wazuh charge automatiquement tous les fichiers dans /var/ossec/etc/shared/
    # et /var/ossec/etc/ qui suivent le pattern local_*.xml
    #
    # C'est la pratique recommandée : elle préserve les customisations lors des mises à jour

    # --- Création du fichier local_rules.xml pour Snort ---
    # On ajoute une section <localfile> dans la config principale
    # Cette section indique à Wazuh de surveiller le fichier Snort

    # Vérifier si la config existe déjà
    if grep -q "<location>${snort_log}</location>" "$ossec_conf"; then
        log_info "Intégration Snort déjà configurée dans ossec.conf"
    else
        # Créer une sauvegarde avant modification
        if [ ! -f "${ossec_conf}.pre-integration.backup" ]; then
            cp "$ossec_conf" "${ossec_conf}.pre-integration.backup"
        fi

        # Ajouter la section localfile AVANT la balise de fermeture </ossec_config>
        # On utilise un fichier temporaire pour éviter les problèmes avec sed
        local tmp_conf
        tmp_conf=$(mktemp)

        # Construction du bloc à ajouter
        local snort_block="
  <!-- === SIEM Africa : Intégration Snort === -->
  <localfile>
    <log_format>snort-fast</log_format>
    <location>${snort_log}</location>
  </localfile>
"

        # Insertion du bloc avant </ossec_config>
        # awk est plus fiable que sed pour les multilignes
        awk -v block="$snort_block" '
            /<\/ossec_config>/ {
                print block
                print $0
                next
            }
            { print }
        ' "$ossec_conf" > "$tmp_conf"

        # Validation : le fichier temporaire doit contenir la ligne ajoutée
        if grep -q "${snort_log}" "$tmp_conf"; then
            mv "$tmp_conf" "$ossec_conf"
            chown root:wazuh "$ossec_conf" 2>/dev/null || true
            chmod 660 "$ossec_conf"
            log_success "Intégration Snort ajoutée dans ossec.conf"
        else
            log_error "Échec de l'ajout de l'intégration"
            rm -f "$tmp_conf"
            return 1
        fi
    fi

    return 0
}

# ============================================================================
# ÉTAPE 2 : Vérification que le fichier Snort existe
# ============================================================================

verify_snort_log_exists() {
    log_info "Vérification du fichier de log Snort..."

    local snort_log="/var/log/snort/alert"

    # Créer le fichier s'il n'existe pas (Snort ne le crée qu'à la première alerte)
    if [ ! -f "$snort_log" ]; then
        log_info "Création du fichier ${snort_log}"
        touch "$snort_log"

        # Permissions pour que Snort écrive et Wazuh lise
        chown snort:snort "$snort_log" 2>/dev/null || chown root:root "$snort_log"
        chmod 644 "$snort_log"
    fi

    # S'assurer que le groupe wazuh peut lire
    # En ajoutant l'user wazuh au groupe snort
    if getent group snort >/dev/null 2>&1 && user_exists "wazuh"; then
        usermod -aG snort wazuh 2>/dev/null || true
    fi

    log_success "Fichier de log Snort prêt : ${snort_log}"
    return 0
}

# ============================================================================
# ÉTAPE 3 : Redémarrage de Wazuh pour prendre en compte la config
# ============================================================================

restart_wazuh() {
    log_info "Redémarrage de Wazuh Manager pour appliquer la config..."

    if systemctl restart wazuh-manager >> "$LOG_FILE" 2>&1; then
        # Attendre le redémarrage
        local max_wait=30
        local waited=0
        while [ $waited -lt $max_wait ]; do
            if systemctl is-active --quiet wazuh-manager; then
                log_success "Wazuh Manager redémarré avec succès"
                return 0
            fi
            sleep 2
            waited=$((waited + 2))
        done

        log_warning "Wazuh Manager n'a pas redémarré après ${max_wait}s"
        log_info  "Debug : sudo journalctl -u wazuh-manager -n 50"
        return 1
    else
        log_error "Échec redémarrage wazuh-manager"
        return 1
    fi
}

# ============================================================================
# ÉTAPE 4 : Test de l'intégration
# ============================================================================

test_integration() {
    log_info "Test de l'intégration Snort ↔ Wazuh..."

    # Test 1 : Les deux services tournent
    if ! systemctl is-active --quiet snort; then
        log_warning "Snort n'est pas actif, l'intégration ne fonctionnera pas"
        log_info  "Démarrez Snort : sudo systemctl start snort"
    else
        log_success "Test 1 : Service Snort actif ✓"
    fi

    if ! systemctl is-active --quiet wazuh-manager; then
        log_error "Wazuh Manager inactif"
        return 1
    else
        log_success "Test 2 : Service Wazuh Manager actif ✓"
    fi

    # Test 3 : Le fichier de log Snort est accessible
    local snort_log="/var/log/snort/alert"
    if [ -r "$snort_log" ]; then
        log_success "Test 3 : Fichier ${snort_log} lisible ✓"
    else
        log_warning "Test 3 : Fichier ${snort_log} non accessible"
    fi

    # Test 4 : La configuration Wazuh contient bien la référence Snort
    if grep -q "${snort_log}" /var/ossec/etc/ossec.conf; then
        log_success "Test 4 : Configuration Wazuh intègre Snort ✓"
    else
        log_error "Test 4 : Configuration Wazuh incorrecte"
        return 1
    fi

    log_success "Intégration Snort ↔ Wazuh validée"
    log_info  "Pour générer une alerte de test depuis une autre machine :"
    log_info  "  nmap -sS ${DETECTED_IP:-<IP_SERVEUR>}"
    log_info  "Puis vérifier :"
    log_info  "  sudo tail -f /var/log/snort/alert"
    log_info  "  sudo tail -f /var/ossec/logs/alerts/alerts.json"

    return 0
}

# ============================================================================
# FONCTION PRINCIPALE DU MODULE
# ============================================================================

integrate_snort_wazuh() {
    log_info "Démarrage de l'intégration Snort ↔ Wazuh..."

    verify_snort_log_exists            || return 1
    configure_wazuh_localfile_snort    || return 1
    restart_wazuh                      || return 1
    test_integration                   || log_warning "Certains tests d'intégration ont échoué"

    log_success "Intégration Snort ↔ Wazuh terminée"
    return 0
}

# ============================================================================
# Fin de modules/06-integration.sh
# ============================================================================
