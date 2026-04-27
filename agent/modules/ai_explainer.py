"""
Module IA explicative — Ollama local pour expliquer les alertes en français.

Caractéristiques :
- Provider : Ollama local (LLaMA 3.2 3B par défaut)
- Cache intelligent : évite de re-générer pour la même signature
- Asynchrone : ne bloque pas le pipeline d'alertes
- Fallback gracieux si Ollama indisponible (l'agent continue)
- Stockage dans la table ai_explanations
- Réutilisation cache : si une explication existe déjà pour la même signature,
  on l'attache avec cache_hits++
"""

import json
import logging
import threading
import uuid
import time
from urllib import request as urlrequest, error as urlerror

from modules import db

log = logging.getLogger("siem-agent.ai")


class AIExplainer:
    """
    Génère et met en cache des explications IA pour les alertes.
    """

    def __init__(self, config):
        self.config = config
        self.db_path = config.get("DB_PATH")
        self.enabled = config.get_bool("AI_ENABLED", True)
        self.provider = config.get("AI_PROVIDER", "ollama")
        self.url = config.get("AI_OLLAMA_URL", "http://localhost:11434")
        self.model = config.get("AI_OLLAMA_MODEL", "llama3.2:3b")
        self.timeout = config.get_int("AI_TIMEOUT_SEC", 30)
        self.cache_enabled = config.get_bool("AI_CACHE_ENABLED", True)
        self.lang = config.get("LANG", "fr")

        # Limiteur de concurrence : max 2 inférences en parallèle
        self._semaphore = threading.Semaphore(2)

    # ========================================================================
    # POINT D'ENTRÉE PRINCIPAL (ASYNC)
    # ========================================================================

    def explain_async(self, alert_id, signature, enriched_data):
        """
        Lance la génération d'explication en arrière-plan.
        Ne bloque PAS l'appelant.
        """
        if not self.enabled:
            return

        thread = threading.Thread(
            target=self._explain_internal,
            args=(alert_id, signature, enriched_data),
            daemon=True,
            name=f"ai-explain-{alert_id}"
        )
        thread.start()

    # ========================================================================
    # GÉNÉRATION INTERNE
    # ========================================================================

    def _explain_internal(self, alert_id, signature, enriched_data):
        """Logique principale : cache → génération → stockage."""
        with self._semaphore:
            try:
                # 1. Chercher dans le cache
                if self.cache_enabled:
                    cached = self._lookup_cache(signature["id"])
                    if cached:
                        self._link_cache_to_alert(alert_id, cached)
                        log.debug(
                            f"Cache IA hit pour signature {signature['id']} "
                            f"(alerte #{alert_id})"
                        )
                        return

                # 2. Pas de cache → générer
                start = time.time()
                explanation = self._generate(signature, enriched_data)
                duration_ms = int((time.time() - start) * 1000)

                if not explanation:
                    log.warning(f"IA n'a pas généré d'explication pour alerte #{alert_id}")
                    return

                # 3. Stocker en BDD
                self._store_explanation(
                    alert_id=alert_id,
                    signature_id=signature["id"],
                    explanation=explanation,
                    duration_ms=duration_ms,
                )

                log.info(
                    f"✓ Explication IA générée pour alerte #{alert_id} "
                    f"({duration_ms}ms, {len(explanation)} car.)"
                )
            except Exception as e:
                log.error(f"Erreur génération IA alerte #{alert_id} : {e}")

    # ========================================================================
    # CACHE
    # ========================================================================

    def _lookup_cache(self, signature_id):
        """
        Cherche une explication existante pour cette signature
        (les explications par signature peuvent être réutilisées).
        """
        try:
            row = db.execute_with_retry(
                self.db_path,
                """
                SELECT id, explanation_fr, explanation_en
                FROM ai_explanations
                WHERE signature_id = ?
                  AND is_cached = 1
                  AND alert_id IS NULL OR alert_id IS NOT NULL
                ORDER BY cache_hits DESC, created_at DESC
                LIMIT 1
                """,
                (signature_id,),
                fetch_one=True
            )
            return dict(row) if row else None
        except Exception as e:
            log.debug(f"Erreur lookup cache IA : {e}")
            return None

    def _link_cache_to_alert(self, alert_id, cached):
        """
        Crée une nouvelle entrée ai_explanations qui réutilise le texte du cache,
        et incrémente cache_hits sur l'entrée d'origine.
        """
        try:
            # Nouvelle entrée pour cette alerte (référence le même texte)
            db.execute_with_retry(
                self.db_path,
                """
                INSERT INTO ai_explanations (
                    explanation_uuid, alert_id, signature_id,
                    explanation_fr, explanation_en,
                    ai_provider, ai_model, is_cached, cache_hits
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, 1, 0)
                """,
                (
                    str(uuid.uuid4()),
                    alert_id,
                    cached.get("explanation_fr"),
                    cached.get("explanation_en"),
                    self.provider,
                    self.model,
                )
            )

            # Incrémenter cache_hits sur l'entrée d'origine
            db.execute_with_retry(
                self.db_path,
                """
                UPDATE ai_explanations
                SET cache_hits = cache_hits + 1,
                    last_used_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (cached["id"],)
            )
        except Exception as e:
            log.debug(f"Erreur link cache : {e}")

    # ========================================================================
    # GÉNÉRATION OLLAMA
    # ========================================================================

    def _build_prompt(self, signature, enriched_data):
        """Construit le prompt pour l'IA."""
        sig_name = signature.get("name", "")
        sig_desc_fr = signature.get("description_fr", "")
        sig_desc_en = signature.get("description", "")
        severity = signature.get("severity", "MEDIUM")

        mitre = (enriched_data or {}).get("mitre", {})
        local_stats = (enriched_data or {}).get("local_stats", {})

        if self.lang == "fr":
            return f"""Tu es un expert en cybersécurité qui explique des alertes SIEM à des admins de PME africaines non-experts.

Voici une alerte :
- Nom : {sig_name}
- Sévérité : {severity}
- Description : {sig_desc_fr}
- MITRE technique : {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}
- MITRE tactique : {mitre.get('tactic_name', 'N/A')}

Contexte local :
- Alertes 24h pour cette IP : {local_stats.get('alerts_24h_for_ip', 0)}
- Attaquant récurrent : {'oui' if local_stats.get('is_recurrent_attacker') else 'non'}
- Déjà bloquée : {'oui' if local_stats.get('has_been_blocked') else 'non'}

Réponds en 100 mots maximum, en français simple. Structure ta réponse en 3 parties :
1. CE QUI SE PASSE : explique l'attaque en termes simples
2. POURQUOI C'EST DANGEREUX : impact concret pour l'entreprise
3. ACTION IMMÉDIATE : 1 action concrète à faire maintenant

Sois direct, pas de jargon technique inutile."""
        else:
            return f"""You are a cybersecurity expert explaining SIEM alerts to non-expert sysadmins.

Alert details:
- Name: {sig_name}
- Severity: {severity}
- Description: {sig_desc_en}
- MITRE technique: {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}

Local context:
- 24h alerts for this IP: {local_stats.get('alerts_24h_for_ip', 0)}
- Recurrent attacker: {'yes' if local_stats.get('is_recurrent_attacker') else 'no'}

Reply in max 100 words, structured as:
1. WHAT'S HAPPENING: simple explanation
2. WHY IT'S DANGEROUS: business impact
3. IMMEDIATE ACTION: 1 concrete step

Be direct, avoid jargon."""

    def _generate(self, signature, enriched_data):
        """Appelle Ollama et retourne le texte généré."""
        if self.provider != "ollama":
            log.warning(f"Provider IA non supporté : {self.provider}")
            return None

        prompt = self._build_prompt(signature, enriched_data)
        url = f"{self.url.rstrip('/')}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 300,
            }
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urlrequest.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"}
            )
            with urlrequest.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                result = json.loads(body)
                return result.get("response", "").strip()
        except urlerror.URLError as e:
            log.warning(f"Ollama indisponible : {e}")
            return None
        except (json.JSONDecodeError, KeyError) as e:
            log.error(f"Réponse Ollama invalide : {e}")
            return None
        except Exception as e:
            log.error(f"Erreur Ollama : {e}")
            return None

    # ========================================================================
    # STOCKAGE
    # ========================================================================

    def _store_explanation(self, alert_id, signature_id, explanation, duration_ms):
        """Stocke une nouvelle explication IA en BDD."""
        try:
            # Stocker selon la langue
            if self.lang == "fr":
                expl_fr = explanation
                expl_en = None
            else:
                expl_fr = None
                expl_en = explanation

            db.execute_with_retry(
                self.db_path,
                """
                INSERT INTO ai_explanations (
                    explanation_uuid, alert_id, signature_id,
                    explanation_fr, explanation_en,
                    ai_provider, ai_model, response_time_ms,
                    is_cached, cache_hits
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
                """,
                (
                    str(uuid.uuid4()),
                    alert_id,
                    signature_id,
                    expl_fr,
                    expl_en,
                    self.provider,
                    self.model,
                    duration_ms,
                )
            )
        except Exception as e:
            log.error(f"Erreur stockage IA : {e}")

    # ========================================================================
    # HEALTHCHECK
    # ========================================================================

    def healthcheck(self):
        """Vérifie qu'Ollama répond."""
        if not self.enabled:
            return {"enabled": False}

        try:
            url = f"{self.url.rstrip('/')}/api/tags"
            with urlrequest.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read())
                models = [m.get("name") for m in data.get("models", [])]
                return {
                    "enabled": True,
                    "available": True,
                    "url": self.url,
                    "configured_model": self.model,
                    "model_loaded": self.model in models,
                    "available_models": models,
                }
        except Exception as e:
            return {
                "enabled": True,
                "available": False,
                "url": self.url,
                "error": str(e),
            }
