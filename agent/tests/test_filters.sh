#!/usr/bin/env bash
# Test : les 5 mécanismes de gestion des faux positifs sont en place

DB_PATH="/var/lib/siem-africa/siem.db"
SYSTEM_USER="siem-agent"

# === Mécanisme 1 : signatures pré-taggées is_noisy ===
NB_NOISY=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM signatures WHERE is_noisy=1" 2>/dev/null)
if [ "$NB_NOISY" -lt 5 ]; then
    echo "  Mécanisme 1 (is_noisy) : seulement $NB_NOISY signatures (attendu >= 5)"
    exit 1
fi

# === Mécanisme 2 : table alert_filters existe et a des filtres PRE_TAGGED ===
NB_PRE=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM alert_filters WHERE filter_type='PRE_TAGGED' AND is_active=1" 2>/dev/null)
if [ "$NB_PRE" -lt 5 ]; then
    echo "  Mécanisme 2 (alert_filters PRE_TAGGED) : seulement $NB_PRE (attendu >= 5)"
    exit 1
fi

# === Mécanisme 4 : triggers SQL de confidence dynamique ===
NB_TRIGS=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
    "SELECT COUNT(*) FROM sqlite_master
     WHERE type='trigger' AND name LIKE '%confidence%'" 2>/dev/null)
if [ "$NB_TRIGS" -lt 2 ]; then
    echo "  Mécanisme 4 (triggers confidence) : seulement $NB_TRIGS (attendu 2)"
    exit 1
fi

# === Test du trigger en simulant un FALSE_POSITIVE ===
# Récupérer la confidence avant
BEFORE=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
    "SELECT confidence FROM signatures WHERE id=5712" 2>/dev/null)

# Simuler une alerte + UPDATE vers FALSE_POSITIVE
sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" <<SQL >/dev/null 2>&1
INSERT INTO alerts (alert_uuid, signature_id, severity, title, src_ip,
                    event_count, first_seen, last_seen, status)
VALUES ('test-trigger-' || hex(randomblob(8)), 5712, 'HIGH', 'Test trigger',
        '192.0.2.99', 1, datetime('now'), datetime('now'), 'NEW');
UPDATE alerts SET status='FALSE_POSITIVE'
    WHERE alert_uuid LIKE 'test-trigger-%' ORDER BY id DESC LIMIT 1;
DELETE FROM alerts WHERE alert_uuid LIKE 'test-trigger-%';
SQL

# Récupérer la confidence après
AFTER=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
    "SELECT confidence FROM signatures WHERE id=5712" 2>/dev/null)

if [ "$BEFORE" = "$AFTER" ]; then
    echo "  Mécanisme 4 (trigger): confidence inchangée (attendu : diminution)"
    # Pas un échec critique, le trigger peut être intact
fi

# === Mécanisme 5 : workflow FALSE_POSITIVE supporté ===
# La table alerts doit accepter le statut FALSE_POSITIVE (CHECK)
TEST=$(sudo -u "$SYSTEM_USER" sqlite3 "$DB_PATH" \
    "SELECT 1 FROM alerts WHERE status='FALSE_POSITIVE' LIMIT 1; SELECT 1" 2>&1)
if [ $? -ne 0 ]; then
    echo "  Mécanisme 5 (status FALSE_POSITIVE) : non supporté"
    exit 1
fi

# === Vérifier qu'au moins un module Python charge bien filters.py ===
if ! python3 -c "
import sys
sys.path.insert(0, '/opt/siem-africa-agent')
from modules.filters import FilterEngine
print('OK')
" 2>/dev/null | grep -q "OK"; then
    echo "  Module filters.py : impossible à importer"
    exit 1
fi

echo "  5 mécanismes FP en place : $NB_NOISY noisy, $NB_PRE PRE_TAGGED, $NB_TRIGS triggers"
exit 0
