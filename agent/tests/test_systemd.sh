#!/usr/bin/env bash
# Test : service systemd actif avec les bonnes capabilities

SERVICE_NAME="siem-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Service installé ?
if ! systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
    echo "  Service systemd non installé"
    exit 1
fi

# Service activé ?
if ! systemctl is-enabled --quiet "$SERVICE_NAME"; then
    echo "  Service non activé au démarrage"
    exit 1
fi

# Service actif ?
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "  Service NON actif"
    echo "  Status : $(systemctl is-active $SERVICE_NAME)"
    echo "  Logs : $(journalctl -u $SERVICE_NAME -n 5 --no-pager 2>/dev/null | tail -3)"
    exit 1
fi

# User correct ?
USER=$(systemctl show "$SERVICE_NAME" -p User --value)
if [ "$USER" != "siem-agent" ]; then
    echo "  User incorrect : $USER (attendu siem-agent)"
    exit 1
fi

# Group correct ?
GROUP=$(systemctl show "$SERVICE_NAME" -p Group --value)
if [ "$GROUP" != "siem-africa" ]; then
    echo "  Group incorrect : $GROUP (attendu siem-africa)"
    exit 1
fi

# Capabilities iptables ?
CAPS=$(systemctl show "$SERVICE_NAME" -p AmbientCapabilities --value)
if ! echo "$CAPS" | grep -q "cap_net_admin"; then
    echo "  CAP_NET_ADMIN manquant (Active Response ne fonctionnera pas)"
    exit 1
fi

# Restart policy ?
RESTART=$(systemctl show "$SERVICE_NAME" -p Restart --value)
if [ "$RESTART" != "on-failure" ]; then
    echo "  Restart=$RESTART (attendu on-failure)"
fi

# Le process tourne ?
MAIN_PID=$(systemctl show "$SERVICE_NAME" -p MainPID --value)
if [ "$MAIN_PID" -le 0 ] 2>/dev/null; then
    echo "  Pas de PID associé"
    exit 1
fi

if ! kill -0 "$MAIN_PID" 2>/dev/null; then
    echo "  Process PID=$MAIN_PID non vivant"
    exit 1
fi

echo "  Service actif (PID $MAIN_PID), user=$USER:$GROUP, caps=$CAPS"
exit 0
