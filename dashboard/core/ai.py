"""
Intégration Ollama côté dashboard :
- Chatbot conversationnel pour analyser les alertes
- Résumé exécutif des dernières 24h
- Suggestions de filtres FP basées sur l'historique
- Réutilise le cache d'explications de l'agent (table ai_explanations)
"""
import json
import logging
import os
from urllib import request as urlrequest, error as urlerror

from core import db

log = logging.getLogger("siem-dashboard.ai")


def _get_ollama_config():
    """Lit la config Ollama depuis la table settings (M2)."""
    cfg = {
        "url": "http://localhost:11434",
        "model": "llama3.2:3b",
        "timeout": 60,
        "enabled": True,
    }
    try:
        rows = db.fetchall(
            "SELECT key, value FROM settings WHERE category = 'ai' AND deleted_at IS NULL"
        )
        for r in rows:
            k, v = r["key"], r["value"]
            if k == "ai_api_endpoint" and v:
                cfg["url"] = v
            elif k == "ai_model" and v:
                cfg["model"] = v
            elif k == "ai_enabled":
                cfg["enabled"] = v in ("1", "true", "yes")
    except Exception as e:
        log.debug(f"Lecture settings AI échouée : {e}")
    return cfg


def is_available():
    """Vérifie qu'Ollama répond."""
    cfg = _get_ollama_config()
    if not cfg["enabled"]:
        return False, "IA désactivée dans les paramètres"
    try:
        url = f"{cfg['url'].rstrip('/')}/api/tags"
        with urlrequest.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
            models = [m.get("name") for m in data.get("models", [])]
            if cfg["model"] not in models:
                return False, f"Modèle {cfg['model']} non chargé. Lancez : ollama pull {cfg['model']}"
            return True, f"Ollama OK ({cfg['model']})"
    except Exception as e:
        return False, f"Ollama indisponible : {e}"


def _call_ollama(prompt, max_tokens=400, temperature=0.3):
    """Appelle l'API /api/generate."""
    cfg = _get_ollama_config()
    if not cfg["enabled"]:
        return None

    url = f"{cfg['url'].rstrip('/')}/api/generate"
    payload = {
        "model": cfg["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
        }
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urlrequest.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urlrequest.urlopen(req, timeout=cfg["timeout"]) as resp:
            result = json.loads(resp.read())
            return result.get("response", "").strip()
    except urlerror.URLError as e:
        log.warning(f"Ollama indisponible : {e}")
        return None
    except Exception as e:
        log.error(f"Erreur Ollama : {e}")
        return None


# ============================================================================
# CHATBOT
# ============================================================================

def chat(user_question, context_alerts=None):
    """
    Répond à une question sur les alertes en utilisant le contexte BDD.

    Args:
        user_question : la question de l'utilisateur
        context_alerts : liste d'alertes à analyser (optionnel)

    Returns: str | None
    """
    # Construire le contexte
    context_str = ""

    if context_alerts:
        context_str += f"\nALERTES À ANALYSER ({len(context_alerts)}):\n"
        for i, a in enumerate(context_alerts[:10], 1):
            context_str += (
                f"{i}. [{a.get('severity', 'MEDIUM')}] "
                f"{a.get('sig_name', a.get('title', 'Sans nom'))[:80]} "
                f"depuis {a.get('src_ip', '?')} "
                f"({a.get('event_count', 1)} events)\n"
            )

    # Récupérer aussi quelques métriques pour donner du contexte
    try:
        metrics = db.get_dashboard_metrics()
        context_str += f"\nMETRIQUES ACTUELLES:\n"
        context_str += f"- Alertes actives : {metrics.get('active_alerts', 0)}\n"
        context_str += f"- Critiques ouvertes : {metrics.get('critical_open', 0)}\n"
        context_str += f"- IPs bloquées : {metrics.get('blocked_ips', 0)}\n"
        context_str += f"- Honeypot hits 24h : {metrics.get('honeypot_24h', 0)}\n"
    except Exception:
        pass

    prompt = f"""Tu es un expert en cybersécurité qui assiste un administrateur SIEM.
Tu réponds en français, de façon claire et concise (maximum 200 mots).
Tu donnes des conseils actionnables basés sur les données fournies.

{context_str}

QUESTION DE L'ADMINISTRATEUR :
{user_question}

Réponds en français, sois direct et pragmatique. Si tu identifies un risque, explique-le.
Si tu suggères une action, sois précis (ex: "bloquer l'IP X via Active Response", "créer un filtre FP pour la signature Y").
"""

    return _call_ollama(prompt, max_tokens=500, temperature=0.4)


# ============================================================================
# RÉSUMÉ EXÉCUTIF
# ============================================================================

def executive_summary():
    """Génère un résumé exécutif des dernières 24h pour managers."""
    try:
        metrics = db.get_dashboard_metrics()
    except Exception:
        return None

    alerts_by_sev = metrics.get("by_severity_24h", {})
    top_attackers = metrics.get("top_attackers", [])
    top_sigs = metrics.get("top_signatures", [])

    context = f"""
DERNIERES 24H :
- Alertes CRITICAL : {alerts_by_sev.get('CRITICAL', 0)}
- Alertes HIGH : {alerts_by_sev.get('HIGH', 0)}
- Alertes MEDIUM : {alerts_by_sev.get('MEDIUM', 0)}
- Alertes actives total : {metrics.get('active_alerts', 0)}
- IPs bloquées actuellement : {metrics.get('blocked_ips', 0)}
- Honeypot hits 24h : {metrics.get('honeypot_24h', 0)}
"""

    if top_attackers:
        context += "\nTOP 3 IPs ATTAQUANTES (7j) :\n"
        for a in top_attackers[:3]:
            context += f"- {a['src_ip']} : {a['nb']} alertes (max {a['max_severity']})\n"

    if top_sigs:
        context += "\nTOP 3 SIGNATURES DECLENCHEES (24h) :\n"
        for s in top_sigs[:3]:
            context += f"- #{s['signature_id']} {s.get('name', '')[:60]} ({s['nb']} hits, {s.get('severity', '?')})\n"

    prompt = f"""Tu es un analyste cybersécurité qui prépare un point quotidien pour le directeur d'une PME.

{context}

Rédige un résumé exécutif EN FRANÇAIS (150 mots maximum) en 3 parties :
1. SITUATION : état général en 1-2 phrases
2. POINTS D'ATTENTION : 2-3 menaces ou patterns à surveiller
3. RECOMMANDATIONS : 2 actions concrètes à entreprendre

Évite le jargon technique. Le directeur n'est pas expert en sécurité.
"""

    return _call_ollama(prompt, max_tokens=400, temperature=0.3)


# ============================================================================
# SUGGESTION FILTRES FP
# ============================================================================

def suggest_fp_filters():
    """
    Analyse les alertes répétitives non résolues et suggère des filtres FP.
    """
    try:
        # Couples (signature, ip) générant beaucoup d'alertes
        candidates = db.fetchall("""
            SELECT a.signature_id, a.src_ip,
                   COUNT(*) AS nb,
                   s.name AS sig_name,
                   s.severity,
                   MAX(a.created_at) AS last_seen
            FROM alerts a
            LEFT JOIN signatures s ON a.signature_id = s.id
            WHERE a.created_at >= datetime('now', '-7 days')
              AND a.src_ip IS NOT NULL
              AND a.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
            GROUP BY a.signature_id, a.src_ip
            HAVING nb >= 10
            ORDER BY nb DESC
            LIMIT 5
        """)
    except Exception as e:
        log.error(f"Erreur suggest_fp : {e}")
        return None

    if not candidates:
        return "Aucune alerte récurrente détectée. Le bruit-killer fait bien son travail. 🎉"

    # Vérifier qu'aucun filtre n'existe déjà pour ces couples
    suggestions = []
    for c in candidates:
        existing = db.fetchone(
            """SELECT id FROM alert_filters
               WHERE signature_id = ? AND src_ip = ? AND is_active = 1""",
            (c["signature_id"], c["src_ip"])
        )
        if not existing:
            suggestions.append(c)

    if not suggestions:
        return "Toutes les alertes récurrentes ont déjà des filtres actifs."

    context = "ALERTES RECURRENTES SANS FILTRE (7 derniers jours) :\n"
    for s in suggestions:
        context += (
            f"- Signature #{s['signature_id']} ({s.get('sig_name', '')[:50]}) "
            f"depuis {s['src_ip']} : {s['nb']} alertes ({s.get('severity', '?')})\n"
        )

    prompt = f"""Tu es un expert SIEM qui aide un admin à réduire le bruit.

{context}

Pour chaque couple (signature, IP), réponds :
- Si c'est probablement un faux positif → recommande un filtre IGNORE
- Si c'est suspect → recommande de garder mais investiguer
- Si c'est clairement malveillant → recommande de bloquer l'IP

Réponds en français en maximum 200 mots, format liste numérotée.
Sois direct et donne des recommandations concrètes.
"""

    return _call_ollama(prompt, max_tokens=500, temperature=0.3)


# ============================================================================
# ANALYSE D'UNE ALERTE SPECIFIQUE
# ============================================================================

def explain_alert(alert_id):
    """
    Explique une alerte. Utilise le cache si disponible.
    Sinon génère une nouvelle explication.
    """
    # 1. Cache existant ?
    cached = db.fetchone(
        """SELECT explanation_fr, explanation_en, ai_model, created_at, cache_hits
           FROM ai_explanations
           WHERE alert_id = ?
           ORDER BY created_at DESC LIMIT 1""",
        (alert_id,)
    )
    if cached and (cached.get("explanation_fr") or cached.get("explanation_en")):
        # Incrémenter cache_hits
        try:
            db.execute(
                "UPDATE ai_explanations SET cache_hits = cache_hits + 1, "
                "last_used_at = CURRENT_TIMESTAMP "
                "WHERE alert_id = ? AND created_at = ?",
                (alert_id, cached["created_at"])
            )
        except Exception:
            pass
        return {
            "explanation": cached.get("explanation_fr") or cached.get("explanation_en"),
            "model": cached.get("ai_model"),
            "cached": True,
        }

    # 2. Générer
    alert = db.get_alert(alert_id)
    if not alert:
        return None

    enriched = {}
    if alert.get("enriched_data"):
        try:
            enriched = json.loads(alert["enriched_data"])
        except Exception:
            pass

    mitre = enriched.get("mitre", {})
    stats = enriched.get("local_stats", {})

    prompt = f"""Tu es un expert cybersécurité qui explique une alerte SIEM à un admin de PME africaine.

ALERTE :
- Sévérité : {alert.get('severity')}
- Signature : {alert.get('sig_name', '')}
- Description : {alert.get('sig_desc', '')}
- IP source : {alert.get('src_ip', 'inconnue')}
- IP destination : {alert.get('dst_ip', 'inconnue')}
- Événements : {alert.get('event_count', 1)}
- MITRE : {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', '')}

CONTEXTE :
- Alertes 24h pour cette IP : {stats.get('alerts_24h_for_ip', 0)}
- Attaquant récurrent : {'oui' if stats.get('is_recurrent_attacker') else 'non'}
- IP déjà bloquée : {'oui' if stats.get('has_been_blocked') else 'non'}

Réponds en français en 100 mots maximum, en 3 parties :
1. CE QUI SE PASSE : explique simplement
2. POURQUOI C'EST DANGEREUX : impact pour l'entreprise
3. ACTION IMMÉDIATE : 1 action concrète

Sois direct, pas de jargon inutile.
"""

    explanation = _call_ollama(prompt, max_tokens=300, temperature=0.3)
    if not explanation:
        return None

    # Stocker en BDD pour réutilisation future
    try:
        import uuid
        db.execute(
            """INSERT INTO ai_explanations (
                explanation_uuid, alert_id, signature_id,
                explanation_fr, ai_provider, ai_model, is_cached, cache_hits
               ) VALUES (?, ?, ?, ?, 'ollama', ?, 1, 0)""",
            (
                str(uuid.uuid4()),
                alert_id,
                alert.get("signature_id"),
                explanation,
                _get_ollama_config()["model"],
            )
        )
    except Exception as e:
        log.debug(f"Erreur cache IA : {e}")

    return {
        "explanation": explanation,
        "model": _get_ollama_config()["model"],
        "cached": False,
    }
