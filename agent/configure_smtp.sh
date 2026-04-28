#!/usr/bin/env bash
# ============================================================================
# SIEM Africa - Module 3 - Configuration SMTP guidee
# ============================================================================
# Reconfigure SMTP avec des explications detaillees a chaque etape.
# Le service est redemarre automatiquement a la fin.
# ============================================================================

LC_ALL=C
LANG=C

if [ ! -t 0 ] && [ -r /dev/tty ]; then
    exec </dev/tty
fi

SYSTEM_GROUP="siem-africa"
CONFIG_DIR="/etc/siem-africa"
ENV_FILE="${CONFIG_DIR}/agent.env"
SERVICE_NAME="siem-agent"
LANG_CHOICE="fr"

C_RED=$'\033[0;31m'
C_GREEN=$'\033[0;32m'
C_YELLOW=$'\033[0;33m'
C_BLUE=$'\033[0;34m'
C_CYAN=$'\033[0;36m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'
C_RESET=$'\033[0m'

log() {
    local level="$1"; shift
    local color=""
    case "$level" in
        OK)    color="$C_GREEN"  ;;
        INFO)  color="$C_BLUE"   ;;
        WARN)  color="$C_YELLOW" ;;
        ERROR) color="$C_RED"    ;;
    esac
    printf "%s[%s]%s %s\n" "$color" "$level" "$C_RESET" "$*"
}

# ============================================================================
# CHECKS
# ============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être lancé en root. Utilisez : sudo bash $0"
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    log ERROR "Module 3 non installé ($ENV_FILE introuvable)"
    log INFO "Lancez d'abord : sudo ./install_agent.sh"
    exit 1
fi

# ============================================================================
# BANNIERE + LANGUE
# ============================================================================

clear || true
echo ""
echo "${C_CYAN}╔════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo "${C_CYAN}║${C_RESET}        ${C_BOLD}SIEM AFRICA — Configuration SMTP guidée${C_RESET}                  ${C_CYAN}║${C_RESET}"
echo "${C_CYAN}╚════════════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
echo "Ce script va vous guider étape par étape pour configurer l'envoi"
echo "d'emails d'alerte. ${C_BOLD}Chaque étape inclut une aide contextuelle.${C_RESET}"
echo ""
echo "Language / Langue :"
echo "  1) Français"
echo "  2) English"
echo -n "Choice [1]: "
read -r lang_input
case "${lang_input:-1}" in
    2) LANG_CHOICE="en" ;;
    *) LANG_CHOICE="fr" ;;
esac

# ============================================================================
# LECTURE CONFIG ACTUELLE
# ============================================================================

read_env_var() {
    local key="$1"
    grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2- | sed 's/^"\(.*\)"$/\1/'
}

EX_HOST=$(read_env_var "SMTP_HOST")
EX_PORT=$(read_env_var "SMTP_PORT")
EX_TLS=$(read_env_var "SMTP_USE_TLS")
EX_USER=$(read_env_var "SMTP_USER")
EX_FROM=$(read_env_var "SMTP_FROM")
EX_EMAIL=$(read_env_var "ALERT_EMAIL")

# ============================================================================
# AFFICHAGE CONFIG ACTUELLE
# ============================================================================

clear || true
echo ""
echo "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "${C_BOLD}Configuration SMTP actuelle :${C_RESET}"
else
    echo "${C_BOLD}Current SMTP configuration:${C_RESET}"
fi
echo "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo "  SMTP_HOST    : ${EX_HOST:-(vide)}"
echo "  SMTP_PORT    : ${EX_PORT:-(vide)}"
echo "  SMTP_USER    : ${EX_USER:-(vide)}"
echo "  SMTP_FROM    : ${EX_FROM:-(vide)}"
echo "  ALERT_EMAIL  : ${EX_EMAIL:-(vide)}"
echo ""
if [ "$LANG_CHOICE" = "fr" ]; then
    echo "${C_DIM}Astuce : appuyez sur Entrée à chaque question pour conserver la valeur actuelle.${C_RESET}"
else
    echo "${C_DIM}Tip: press Enter at each question to keep current value.${C_RESET}"
fi
echo ""
echo -n "Continuer ? [O/n] : "
read -r confirm
case "${confirm:-O}" in
    [nN]*) log INFO "Configuration annulée"; exit 0 ;;
esac

# ============================================================================
# ETAPE 1 : SERVEUR SMTP
# ============================================================================

echo ""
echo "${C_CYAN}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_BOLD}💡 ÉTAPE 1/7 — Serveur SMTP${C_RESET}                                          ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}├──────────────────────────────────────────────────────────────────────┤${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} Le serveur SMTP est l'adresse du \"bureau de poste\" qui va envoyer    ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} les emails d'alerte. La valeur dépend de votre fournisseur d'email.  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_GREEN}Valeurs courantes :${C_RESET}                                                  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • Gmail              → ${C_BOLD}smtp.gmail.com${C_RESET}                              ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • Outlook / Hotmail  → ${C_BOLD}smtp-mail.outlook.com${C_RESET}                       ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • Yahoo              → ${C_BOLD}smtp.mail.yahoo.com${C_RESET}                         ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • OVH                → ${C_BOLD}ssl0.ovh.net${C_RESET}                                ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • iCloud             → ${C_BOLD}smtp.mail.me.com${C_RESET}                            ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • Zoho               → ${C_BOLD}smtp.zoho.com${C_RESET}                               ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"

echo -n "  → Serveur SMTP [${EX_HOST:-smtp.gmail.com}] : "
read -r SMTP_HOST
SMTP_HOST="${SMTP_HOST:-${EX_HOST:-smtp.gmail.com}}"

# ============================================================================
# ETAPE 2 : PORT
# ============================================================================

echo ""
echo "${C_CYAN}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_BOLD}💡 ÉTAPE 2/7 — Port SMTP${C_RESET}                                             ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}├──────────────────────────────────────────────────────────────────────┤${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} Le port est la \"porte d'entrée\" du serveur SMTP.                     ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_GREEN}Valeurs courantes :${C_RESET}                                                  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • ${C_BOLD}587${C_RESET}  → ${C_GREEN}Recommandé${C_RESET} (avec STARTTLS — moderne, sécurisé)         ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • ${C_BOLD}465${C_RESET}  → SSL/TLS direct (ancienne méthode)                       ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • ${C_BOLD}25${C_RESET}   → Non chiffré (à éviter)                                  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_YELLOW}Pour Gmail / Outlook / Yahoo : utilisez ${C_BOLD}587${C_RESET}                          ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"

echo -n "  → Port SMTP [${EX_PORT:-587}] : "
read -r p
SMTP_PORT="${p:-${EX_PORT:-587}}"

# ============================================================================
# ETAPE 3 : STARTTLS
# ============================================================================

echo ""
echo "${C_CYAN}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_BOLD}💡 ÉTAPE 3/7 — Chiffrement STARTTLS${C_RESET}                                  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}├──────────────────────────────────────────────────────────────────────┤${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} STARTTLS chiffre la connexion entre l'agent et le serveur SMTP.      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} Sans chiffrement, votre mot de passe SMTP passerait ${C_RED}en clair${C_RESET}         ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} sur le réseau, ce qui est dangereux.                                 ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_GREEN}✓ Toujours répondre OUI (1)${C_RESET}                                          ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_DIM}Sauf si vous utilisez le port 465 (déjà chiffré directement).${C_RESET}        ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"

echo -n "  → Utiliser STARTTLS ? [1=oui/0=non] [${EX_TLS:-1}] : "
read -r tls
case "${tls:-${EX_TLS:-1}}" in
    0|n|N) SMTP_USE_TLS="0" ;;
    *) SMTP_USE_TLS="1" ;;
esac

# ============================================================================
# ETAPE 4 : UTILISATEUR
# ============================================================================

echo ""
echo "${C_CYAN}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_BOLD}💡 ÉTAPE 4/7 — Utilisateur SMTP${C_RESET}                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}├──────────────────────────────────────────────────────────────────────┤${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_RED}⚠ Erreur fréquente : ne mettez PAS juste votre prénom !${C_RESET}              ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} Mettez ${C_BOLD}votre adresse email complète${C_RESET}.                                 ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_GREEN}Exemples corrects :${C_RESET}                                                  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   ${C_GREEN}✓${C_RESET} siemafrica45@gmail.com                                          ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   ${C_GREEN}✓${C_RESET} admin@masociete.com                                              ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_RED}Exemples INCORRECTS :${C_RESET}                                                ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   ${C_RED}✗${C_RESET} Lyren           (juste un prénom)                                ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   ${C_RED}✗${C_RESET} siemafrica45    (sans @gmail.com)                                ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   ${C_RED}✗${C_RESET} admin           (juste un nom d'utilisateur)                     ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"

echo -n "  → Utilisateur SMTP (${C_BOLD}email complet${C_RESET}) [${EX_USER:-(vide)}] : "
read -r SMTP_USER
[ -z "$SMTP_USER" ] && SMTP_USER="$EX_USER"

# Validation : warn si pas d'email
if [ -n "$SMTP_USER" ] && ! echo "$SMTP_USER" | grep -q "@"; then
    echo ""
    log WARN "L'utilisateur '$SMTP_USER' ne contient pas '@'"
    log WARN "Gmail va certainement refuser. Il faut une adresse email complète."
    echo -n "  Continuer quand même ? [o/N] : "
    read -r confirm
    case "${confirm:-N}" in
        [oOyY]*) ;;
        *)
            echo -n "  → Utilisateur SMTP corrigé : "
            read -r SMTP_USER
            ;;
    esac
fi

# ============================================================================
# ETAPE 5 : MOT DE PASSE
# ============================================================================

SMTP_PASSWORD=""
if [ -n "$SMTP_USER" ]; then

    # Détection Gmail
    IS_GMAIL=0
    if echo "$SMTP_HOST" | grep -qi "gmail" || echo "$SMTP_USER" | grep -qi "@gmail.com"; then
        IS_GMAIL=1
    fi

    echo ""
    echo "${C_CYAN}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
    echo "${C_CYAN}│${C_RESET} ${C_BOLD}💡 ÉTAPE 5/7 — Mot de passe SMTP${C_RESET}                                     ${C_CYAN}│${C_RESET}"
    echo "${C_CYAN}├──────────────────────────────────────────────────────────────────────┤${C_RESET}"

    if [ "$IS_GMAIL" -eq 1 ]; then
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_RED}⚠ IMPORTANT : Gmail bloque le mot de passe normal depuis 2022.${C_RESET}        ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} Vous devez créer un ${C_BOLD}\"App Password\"${C_RESET} (mot de passe d'application)    ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} — un code spécial de ${C_BOLD}16 caractères${C_RESET} généré par Google.               ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_GREEN}═══ COMMENT CRÉER UN APP PASSWORD ═══${C_RESET}                                ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_BOLD}1.${C_RESET} Activer la validation 2 étapes (si pas déjà fait) :              ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}    ${C_CYAN}https://myaccount.google.com/signinoptions/two-step-verification${C_RESET}    ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_BOLD}2.${C_RESET} Créer l'App Password :                                            ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}    ${C_CYAN}https://myaccount.google.com/apppasswords${C_RESET}                          ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_BOLD}3.${C_RESET} Tapez \"SIEM Africa\" comme nom d'application → Créer              ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_BOLD}4.${C_RESET} Google affiche un code style ${C_GREEN}\"abcd efgh ijkl mnop\"${C_RESET}              ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}    Copiez-le ${C_RED}IMMÉDIATEMENT${C_RESET} (il ne sera plus jamais affiché).         ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_BOLD}5.${C_RESET} Collez-le ci-dessous (avec ou sans espaces, peu importe).        ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_DIM}Le mot de passe ne s'affichera pas pendant la saisie (sécurité).${C_RESET}     ${C_CYAN}│${C_RESET}"
    else
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} Mot de passe pour l'utilisateur ${C_BOLD}${SMTP_USER}${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_DIM}Le mot de passe ne s'affichera pas (sécurité).${C_RESET}                       ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET} ${C_YELLOW}Selon votre fournisseur :${C_RESET}                                            ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}   • Outlook / Office 365 : peut nécessiter un App Password aussi    ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}   • Yahoo : nécessite un App Password (Account Security)            ${C_CYAN}│${C_RESET}"
        echo "${C_CYAN}│${C_RESET}   • OVH / autres : votre mot de passe email normal                  ${C_CYAN}│${C_RESET}"
    fi
    echo "${C_CYAN}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"

    if [ "$IS_GMAIL" -eq 1 ]; then
        echo ""
        echo "  ${C_YELLOW}Avez-vous déjà créé l'App Password ?${C_RESET}"
        echo "    1) Oui, je l'ai prêt"
        echo "    2) Non — affiche-moi à nouveau les liens"
        echo "    3) Garder le mot de passe actuel"
        echo -n "  → Choix [1] : "
        read -r pwd_choice

        case "${pwd_choice:-1}" in
            2)
                echo ""
                echo "  ${C_GREEN}═══ Liens à ouvrir dans votre navigateur ═══${C_RESET}"
                echo ""
                echo "  ${C_BOLD}1.${C_RESET} Activer 2FA (si pas fait) :"
                echo "     ${C_CYAN}https://myaccount.google.com/signinoptions/two-step-verification${C_RESET}"
                echo ""
                echo "  ${C_BOLD}2.${C_RESET} Créer App Password \"SIEM Africa\" :"
                echo "     ${C_CYAN}https://myaccount.google.com/apppasswords${C_RESET}"
                echo ""
                echo -n "  Une fois le code 16 caractères copié, appuyez sur Entrée..."
                read -r _
                ;;
            3)
                SMTP_PASSWORD=""
                log INFO "Mot de passe inchangé"
                ;;
        esac
    fi

    if [ "${pwd_choice:-1}" != "3" ]; then
        echo -n "  → Mot de passe SMTP (${C_DIM}invisible pendant la saisie${C_RESET}) : "
        stty -echo 2>/dev/null
        read -r SMTP_PASSWORD
        stty echo 2>/dev/null
        echo ""

        # Validation longueur Gmail
        if [ "$IS_GMAIL" -eq 1 ] && [ -n "$SMTP_PASSWORD" ]; then
            PWD_LEN=$(printf '%s' "$SMTP_PASSWORD" | tr -d ' ' | wc -c)
            if [ "$PWD_LEN" -ne 16 ]; then
                log WARN "App Password fait $PWD_LEN caractères (attendu : 16 sans les espaces)"
                log WARN "Vérifiez que vous avez collé tout le code Google"
            fi
        fi
    fi
fi

# ============================================================================
# ETAPE 6 : FROM
# ============================================================================

DEFAULT_FROM="${EX_FROM:-${SMTP_USER:-agent@$(hostname -f 2>/dev/null || hostname)}}"

echo ""
echo "${C_CYAN}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_BOLD}💡 ÉTAPE 6/7 — Adresse expéditeur (From)${C_RESET}                              ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}├──────────────────────────────────────────────────────────────────────┤${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} C'est l'adresse qui apparaîtra dans le champ ${C_BOLD}\"De :\"${C_RESET}                  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} quand vous recevrez un email d'alerte.                              ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_GREEN}Recommandation :${C_RESET}                                                     ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   Mettez la même adresse que le SMTP_USER ci-dessus.                ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_YELLOW}⚠ Pour Gmail :${C_RESET} si vous mettez une adresse différente,                ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} Gmail va automatiquement la réécrire en ${SMTP_USER}.                ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_DIM}Vous pouvez aussi personnaliser :${C_RESET}                                    ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   ${C_DIM}\"SIEM Africa <${SMTP_USER}>\"${C_RESET}"
echo "${C_CYAN}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"

echo -n "  → Adresse From [${DEFAULT_FROM}] : "
read -r SMTP_FROM
SMTP_FROM="${SMTP_FROM:-$DEFAULT_FROM}"

# ============================================================================
# ETAPE 7 : DESTINATAIRE
# ============================================================================

DEFAULT_EMAIL="${EX_EMAIL:-${SMTP_USER}}"

echo ""
echo "${C_CYAN}┌──────────────────────────────────────────────────────────────────────┐${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_BOLD}💡 ÉTAPE 7/7 — Email destinataire des alertes${C_RESET}                         ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}├──────────────────────────────────────────────────────────────────────┤${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} Adresse(s) email qui ${C_BOLD}recevront${C_RESET} les alertes de sécurité.                  ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_GREEN}Exemples :${C_RESET}                                                            ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • Une seule personne : ${C_BOLD}admin@masociete.com${C_RESET}                          ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}   • Plusieurs (séparées par virgule) :                              ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}     ${C_BOLD}admin@masociete.com,securite@masociete.com${C_RESET}                       ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET}                                                                      ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} ${C_YELLOW}Astuce :${C_RESET} ça peut être la même adresse que SMTP_USER                 ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}│${C_RESET} (vous vous envoyez les alertes à vous-même), c'est très courant.    ${C_CYAN}│${C_RESET}"
echo "${C_CYAN}└──────────────────────────────────────────────────────────────────────┘${C_RESET}"

echo -n "  → Email destinataire [${DEFAULT_EMAIL}] : "
read -r ALERT_EMAIL
ALERT_EMAIL="${ALERT_EMAIL:-$DEFAULT_EMAIL}"

# ============================================================================
# RECAP + CONFIRMATION
# ============================================================================

echo ""
echo "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo "${C_BOLD}Récapitulatif :${C_RESET}"
echo "${C_CYAN}════════════════════════════════════════════════════════════════════════${C_RESET}"
echo ""
echo "  SMTP_HOST     : $SMTP_HOST"
echo "  SMTP_PORT     : $SMTP_PORT"
echo "  SMTP_USE_TLS  : $SMTP_USE_TLS"
echo "  SMTP_USER     : $SMTP_USER"
if [ -n "$SMTP_PASSWORD" ]; then
    echo "  SMTP_PASSWORD : ${C_GREEN}*** (modifié)${C_RESET}"
else
    echo "  SMTP_PASSWORD : ${C_DIM}(inchangé)${C_RESET}"
fi
echo "  SMTP_FROM     : $SMTP_FROM"
echo "  ALERT_EMAIL   : $ALERT_EMAIL"
echo ""

echo -n "Sauvegarder cette configuration et tester l'envoi ? [O/n] : "
read -r confirm_save
case "${confirm_save:-O}" in
    [nN]*)
        log INFO "Configuration annulée. Aucun fichier modifié."
        exit 0
        ;;
esac

# ============================================================================
# SAUVEGARDE
# ============================================================================

cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

update_env_var() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}=" "$ENV_FILE"; then
        local escaped_value=$(printf '%s\n' "$value" | sed 's/[\/&]/\\&/g')
        sed -i "s|^${key}=.*|${key}=${escaped_value}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

update_env_var "SMTP_HOST" "$SMTP_HOST"
update_env_var "SMTP_PORT" "$SMTP_PORT"
update_env_var "SMTP_USE_TLS" "$SMTP_USE_TLS"
update_env_var "SMTP_USER" "$SMTP_USER"
[ -n "$SMTP_PASSWORD" ] && update_env_var "SMTP_PASSWORD" "$SMTP_PASSWORD"
update_env_var "SMTP_FROM" "$SMTP_FROM"
update_env_var "ALERT_EMAIL" "$ALERT_EMAIL"

chown root:"$SYSTEM_GROUP" "$ENV_FILE"
chmod 640 "$ENV_FILE"

log OK "Configuration enregistrée → $ENV_FILE"

# ============================================================================
# TEST SMTP
# ============================================================================

# Récupérer le password actuel si pas modifié
if [ -z "$SMTP_PASSWORD" ]; then
    SMTP_PASSWORD=$(read_env_var "SMTP_PASSWORD")
fi

if [ -n "$SMTP_HOST" ] && [ -n "$ALERT_EMAIL" ]; then
    log INFO "Envoi d'un email de test à $ALERT_EMAIL"

    if SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_USER="$SMTP_USER" \
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

body = """SIEM Africa - Test SMTP reussi !

Si vous recevez ce message, votre agent peut maintenant vous envoyer
des alertes de securite par email.

Cordialement,
Agent SIEM Africa
"""

msg = MIMEText(body, "plain", "utf-8")
msg["From"] = sender
msg["To"] = to
msg["Subject"] = "[SIEM Africa] Test SMTP reussi"

try:
    if port == 465:
        s = smtplib.SMTP_SSL(host, port, timeout=20)
    else:
        s = smtplib.SMTP(host, port, timeout=20)
        if use_tls:
            s.starttls()
    if user and pwd:
        s.login(user, pwd)
    s.sendmail(sender, [r.strip() for r in to.split(",") if r.strip()], msg.as_string())
    s.quit()
    sys.exit(0)
except smtplib.SMTPAuthenticationError as e:
    print(f"AUTHENTIFICATION ECHOUEE", file=sys.stderr)
    print(f"  Verifiez SMTP_USER (email complet ?) et le mot de passe (App Password pour Gmail)", file=sys.stderr)
    print(f"  Detail: {e}", file=sys.stderr)
    sys.exit(2)
except Exception as e:
    print(f"Erreur SMTP : {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
    then
        log OK "Email de test envoyé avec succès !"
        echo ""
        echo "  ${C_GREEN}✓ Vérifiez votre boîte $ALERT_EMAIL${C_RESET}"
        echo "  ${C_DIM}(pensez aussi à regarder le dossier ${C_BOLD}Spam${C_RESET}${C_DIM})${C_RESET}"
    else
        echo ""
        log WARN "Test SMTP échoué — la configuration est quand même enregistrée"
        echo ""
        echo "  ${C_YELLOW}Causes possibles :${C_RESET}"
        echo "    1. SMTP_USER incorrect (doit être l'email complet, pas juste le prénom)"
        echo "    2. App Password incorrect (pour Gmail : 16 caractères)"
        echo "    3. 2FA non activée sur le compte Gmail"
        echo "    4. Pare-feu bloquant le port $SMTP_PORT"
        echo ""
        echo "  ${C_CYAN}Relancez ce script pour corriger : sudo ./configure_smtp.sh${C_RESET}"
    fi
fi

# ============================================================================
# RESTART SERVICE
# ============================================================================

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    log INFO "Redémarrage du service $SERVICE_NAME"
    if systemctl restart "$SERVICE_NAME"; then
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log OK "Service redémarré"
        fi
    fi
fi

echo ""
log OK "Reconfiguration SMTP terminée"
echo ""

exit 0
