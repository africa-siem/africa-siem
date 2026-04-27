#!/usr/bin/env bash
# Test : envoi SMTP de bout en bout (si SMTP configuré)

ENV_FILE="/etc/siem-africa/agent.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "  Config introuvable : $ENV_FILE"
    exit 1
fi

# Lire la config SMTP
SMTP_HOST=$(grep -E "^SMTP_HOST=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)
SMTP_PORT=$(grep -E "^SMTP_PORT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)
SMTP_USER=$(grep -E "^SMTP_USER=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)
SMTP_PASSWORD=$(grep -E "^SMTP_PASSWORD=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)
SMTP_USE_TLS=$(grep -E "^SMTP_USE_TLS=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)
SMTP_FROM=$(grep -E "^SMTP_FROM=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)
ALERT_EMAIL=$(grep -E "^ALERT_EMAIL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-)

if [ -z "$SMTP_HOST" ] || [ "$SMTP_HOST" = "localhost" ]; then
    echo "  SMTP non configuré (config par défaut). Test ignoré (OK)."
    exit 0
fi

if [ -z "$ALERT_EMAIL" ]; then
    echo "  ALERT_EMAIL vide. Test ignoré (OK)."
    exit 0
fi

# Lancer le test SMTP
SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_USER="$SMTP_USER" \
SMTP_PASSWORD="$SMTP_PASSWORD" SMTP_USE_TLS="$SMTP_USE_TLS" \
SMTP_FROM="$SMTP_FROM" ALERT_EMAIL="$ALERT_EMAIL" \
python3 - <<'PYEOF'
import os, sys, smtplib
from email.mime.text import MIMEText

host = os.environ.get("SMTP_HOST")
port = int(os.environ.get("SMTP_PORT") or "587")
user = os.environ.get("SMTP_USER", "")
pwd  = os.environ.get("SMTP_PASSWORD", "")
use_tls = os.environ.get("SMTP_USE_TLS", "1") in ("1","true","yes","on")
sender  = os.environ.get("SMTP_FROM", "agent@localhost")
to      = os.environ.get("ALERT_EMAIL", "")

msg = MIMEText("SIEM Africa — Test SMTP automatisé. Tout fonctionne !", "plain", "utf-8")
msg["From"] = sender
msg["To"] = to
msg["Subject"] = "[SIEM Africa] Test automatisé tests/test_email.sh"

try:
    if port == 465:
        s = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        s = smtplib.SMTP(host, port, timeout=15)
        if use_tls:
            s.starttls()
    if user and pwd:
        s.login(user, pwd)
    s.sendmail(sender, [to], msg.as_string())
    s.quit()
    print(f"  Email test envoyé à {to}", file=sys.stderr)
    sys.exit(0)
except Exception as e:
    print(f"  Erreur SMTP : {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

RC=$?
if [ $RC -eq 0 ]; then
    echo "  Email test envoyé avec succès à $ALERT_EMAIL"
    exit 0
else
    echo "  Échec envoi SMTP"
    exit 1
fi
