"""SIEM Africa - Views Django"""
import json
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.contrib import messages
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect

from core import db, ai
from core.auth import verify_password, hash_password, has_permission

log = logging.getLogger("siem-dashboard.views")


# ============================================================================
# AUTH
# ============================================================================

def login_view(request):
    if request.siem_user:
        return redirect('home')

    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        next_url = request.POST.get('next') or request.GET.get('next') or '/'

        if not email or not password:
            messages.error(request, "Email et mot de passe requis")
            return render(request, 'login.html', {'next': next_url})

        user = db.get_user_by_email(email)
        if not user:
            messages.error(request, "Identifiants incorrects")
            return render(request, 'login.html', {'next': next_url})

        # Vérifier le compte
        if user.get('account_locked'):
            messages.error(request, "Compte verrouillé. Contactez l'administrateur.")
            return render(request, 'login.html', {'next': next_url})

        if not verify_password(password, user['password_hash']):
            db.increment_failed_login(user['id'])
            messages.error(request, "Identifiants incorrects")
            return render(request, 'login.html', {'next': next_url})

        # Login OK
        db.update_last_login(user['id'])
        request.session['siem_user_id'] = user['id']
        request.session.set_expiry(8 * 3600)

        db.log_audit(
            user_id=user['id'],
            user_email=user['email'],
            action='LOGIN_SUCCESS',
            action_category='AUTH',
            ip_address=_get_client_ip(request),
        )

        # Force change password ?
        if user.get('must_change_password'):
            return redirect('change_password')

        return redirect(next_url if next_url.startswith('/') else '/')

    return render(request, 'login.html', {
        'next': request.GET.get('next', '/'),
    })


def logout_view(request):
    if request.siem_user:
        db.log_audit(
            user_id=request.siem_user['id'],
            user_email=request.siem_user['email'],
            action='LOGOUT',
            action_category='AUTH',
            ip_address=_get_client_ip(request),
        )
    request.session.flush()
    messages.success(request, "Déconnexion réussie")
    return redirect('login')


def change_password_view(request):
    user = request.siem_user

    if request.method == 'POST':
        old_pwd = request.POST.get('old_password', '')
        new_pwd = request.POST.get('new_password', '')
        confirm = request.POST.get('confirm_password', '')

        # Si forcé, l'ancien n'est pas requis
        if not user.get('must_change_password'):
            if not verify_password(old_pwd, user['password_hash']):
                messages.error(request, "Mot de passe actuel incorrect")
                return render(request, 'change_password.html')

        if new_pwd != confirm:
            messages.error(request, "Les mots de passe ne correspondent pas")
            return render(request, 'change_password.html')

        if len(new_pwd) < 8:
            messages.error(request, "Le mot de passe doit faire au moins 8 caractères")
            return render(request, 'change_password.html')

        new_hash = hash_password(new_pwd)
        db.update_password(user['id'], new_hash)

        db.log_audit(
            user_id=user['id'],
            user_email=user['email'],
            action='PASSWORD_CHANGED',
            action_category='AUTH',
            ip_address=_get_client_ip(request),
        )

        messages.success(request, "Mot de passe modifié")
        return redirect('home')

    return render(request, 'change_password.html')


# ============================================================================
# DASHBOARD HOME
# ============================================================================

def home_view(request):
    metrics = db.get_dashboard_metrics()

    # Dernières 10 alertes
    recent_alerts = db.list_alerts(limit=10)

    return render(request, 'dashboard.html', {
        'metrics': metrics,
        'recent_alerts': recent_alerts,
    })


# ============================================================================
# ALERTES
# ============================================================================

def alerts_list(request):
    severity = request.GET.get('severity') or None
    status = request.GET.get('status') or 'ACTIVE'
    page = int(request.GET.get('page', 1))
    per_page = 50
    offset = (page - 1) * per_page

    alerts = db.list_alerts(severity=severity, status=status,
                             limit=per_page, offset=offset)
    total = db.count_alerts(severity=severity, status=status)

    return render(request, 'alerts.html', {
        'alerts': alerts,
        'severity': severity,
        'status': status,
        'page': page,
        'per_page': per_page,
        'total': total,
        'has_next': (offset + per_page) < total,
        'has_prev': page > 1,
    })


def alert_detail(request, alert_id):
    alert = db.get_alert(alert_id)
    if not alert:
        messages.error(request, "Alerte introuvable")
        return redirect('alerts_list')

    ai = db.get_alert_ai_explanation(alert_id)

    # Parse enriched_data
    enriched = {}
    if alert.get('enriched_data'):
        try:
            enriched = json.loads(alert['enriched_data'])
        except (ValueError, TypeError):
            pass

    return render(request, 'alert_detail.html', {
        'alert': alert,
        'ai': ai,
        'enriched': enriched,
    })


@require_POST
@csrf_protect
def alert_action(request, alert_id):
    """Marquer comme RESOLVED, FALSE_POSITIVE, ACKNOWLEDGED, etc."""
    if not has_permission(request.siem_user, 'alerts.update'):
        return HttpResponseForbidden("Permission refusée")

    action = request.POST.get('action')
    notes = request.POST.get('notes', '')

    valid_actions = ['ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED',
                     'FALSE_POSITIVE', 'IGNORED']
    if action not in valid_actions:
        return HttpResponseBadRequest("Action invalide")

    alert = db.get_alert(alert_id)
    if not alert:
        return HttpResponseBadRequest("Alerte introuvable")

    db.update_alert_status(alert_id, action, request.siem_user['id'], notes)

    db.log_audit(
        user_id=request.siem_user['id'],
        user_email=request.siem_user['email'],
        action=f'ALERT_{action}',
        action_category='ALERT',
        target_table='alerts',
        target_id=alert_id,
        details=notes,
        ip_address=_get_client_ip(request),
    )

    messages.success(request, f"Alerte marquée {action}")
    return redirect('alert_detail', alert_id=alert_id)


# ============================================================================
# FILTRES FAUX POSITIFS
# ============================================================================

def filters_list(request):
    show_inactive = request.GET.get('all') == '1'
    filters = db.list_filters(active_only=not show_inactive)

    return render(request, 'filters.html', {
        'filters': filters,
        'show_inactive': show_inactive,
    })


def filter_create(request):
    if not has_permission(request.siem_user, 'filters.create'):
        return HttpResponseForbidden("Permission refusée")

    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        signature_id = request.POST.get('signature_id') or None
        src_ip = request.POST.get('src_ip', '').strip() or None
        action = request.POST.get('action', 'IGNORE')
        reason = request.POST.get('reason', '').strip()

        if not name:
            messages.error(request, "Le nom est obligatoire")
            return redirect('filter_create')

        if not signature_id and not src_ip:
            messages.error(request, "Renseignez au moins un signature_id ou une src_ip")
            return redirect('filter_create')

        try:
            signature_id = int(signature_id) if signature_id else None
        except (ValueError, TypeError):
            signature_id = None

        filter_id = db.create_filter(
            name=name,
            signature_id=signature_id,
            src_ip=src_ip,
            action=action,
            reason=reason,
            user_id=request.siem_user['id'],
            filter_type='MANUAL',
        )

        db.log_audit(
            user_id=request.siem_user['id'],
            user_email=request.siem_user['email'],
            action='FILTER_CREATED',
            action_category='FILTER',
            target_table='alert_filters',
            target_id=filter_id,
            details=f"name={name} sig={signature_id} ip={src_ip} action={action}",
            ip_address=_get_client_ip(request),
        )

        messages.success(request, f"Filtre #{filter_id} créé")
        return redirect('filters_list')

    return render(request, 'filter_form.html')


@require_POST
@csrf_protect
def filter_delete(request, filter_id):
    if not has_permission(request.siem_user, 'filters.delete'):
        return HttpResponseForbidden("Permission refusée")

    db.delete_filter(filter_id)
    db.log_audit(
        user_id=request.siem_user['id'],
        user_email=request.siem_user['email'],
        action='FILTER_DELETED',
        action_category='FILTER',
        target_table='alert_filters',
        target_id=filter_id,
        ip_address=_get_client_ip(request),
    )
    messages.success(request, f"Filtre #{filter_id} désactivé")
    return redirect('filters_list')


def filter_signature_search(request):
    """Endpoint AJAX pour autocomplétion des signatures."""
    query = request.GET.get('q', '').strip()
    if len(query) < 2:
        return JsonResponse({'results': []})

    results = db.search_signatures(query, limit=20)
    return JsonResponse({'results': results})


# ============================================================================
# IPs BLOQUEES
# ============================================================================

def blocked_ips_list(request):
    show_inactive = request.GET.get('all') == '1'
    ips = db.list_blocked_ips(active_only=not show_inactive)
    return render(request, 'blocked_ips.html', {
        'ips': ips,
        'show_inactive': show_inactive,
    })


@require_POST
@csrf_protect
def unblock_ip(request, ip_id):
    if not has_permission(request.siem_user, 'blocks.delete'):
        return HttpResponseForbidden("Permission refusée")

    db.unblock_ip_db(ip_id, request.siem_user['id'],
                     reason=request.POST.get('reason', 'Manuel'))
    db.log_audit(
        user_id=request.siem_user['id'],
        user_email=request.siem_user['email'],
        action='IP_UNBLOCKED',
        action_category='BLOCK',
        target_table='blocked_ips',
        target_id=ip_id,
        ip_address=_get_client_ip(request),
    )
    messages.success(request, "IP débloquée. L'agent retirera la règle iptables.")
    return redirect('blocked_ips_list')


# ============================================================================
# HEALTH (pour monitoring)
# ============================================================================

def health(request):
    try:
        db.fetchone("SELECT 1")
        return JsonResponse({'status': 'ok'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'error': str(e)}, status=500)


# ============================================================================
# HELPERS
# ============================================================================

def _get_client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


# ============================================================================
# MITRE ATT&CK
# ============================================================================

def mitre_matrix(request):
    matrix = db.get_mitre_matrix()
    return render(request, 'mitre.html', {'matrix': matrix})


def mitre_technique_detail(request, technique_id):
    alerts = db.get_technique_alerts(technique_id)
    technique = db.fetchone(
        """SELECT mt.*, mt2.tactic_id, mt2.name AS tactic_name
           FROM mitre_techniques mt
           JOIN mitre_tactics mt2 ON mt.tactic_id = mt2.id
           WHERE mt.technique_id = ?""",
        (technique_id,)
    )
    return render(request, 'mitre_detail.html', {
        'technique': technique,
        'alerts': alerts,
    })


# ============================================================================
# HONEYPOT
# ============================================================================

def honeypot_view(request):
    hits = db.list_honeypot_hits(limit=200)
    stats = db.get_honeypot_stats()
    return render(request, 'honeypot.html', {
        'hits': hits,
        'stats': stats,
    })


# ============================================================================
# USERS / RBAC
# ============================================================================

def users_list(request):
    if not has_permission(request.siem_user, 'users.read'):
        return HttpResponseForbidden("Permission refusée")
    users = db.list_users()
    return render(request, 'users.html', {'users': users})


def user_create(request):
    if not has_permission(request.siem_user, 'users.create'):
        return HttpResponseForbidden("Permission refusée")

    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        role_id = request.POST.get('role_id')
        full_name = request.POST.get('full_name', '').strip()

        if not email or not password or not role_id:
            messages.error(request, "Tous les champs sont requis")
            return redirect('user_create')

        # Vérifier email unique
        existing = db.get_user_by_email(email)
        if existing:
            messages.error(request, "Cet email existe déjà")
            return redirect('user_create')

        if len(password) < 8:
            messages.error(request, "Le mot de passe doit faire au moins 8 caractères")
            return redirect('user_create')

        password_hash = hash_password(password)
        user_id = db.create_user(email, password_hash, int(role_id), full_name)

        db.log_audit(
            user_id=request.siem_user['id'],
            user_email=request.siem_user['email'],
            action='USER_CREATED',
            action_category='USER',
            target_table='users',
            target_id=user_id,
            details=f"new user: {email}",
            ip_address=_get_client_ip(request),
        )

        messages.success(request, f"Utilisateur {email} créé. L'utilisateur devra changer son mot de passe à la 1ère connexion.")
        return redirect('users_list')

    roles = db.list_roles()
    return render(request, 'user_form.html', {'roles': roles})


@require_POST
@csrf_protect
def user_toggle_active(request, user_id):
    if not has_permission(request.siem_user, 'users.update'):
        return HttpResponseForbidden("Permission refusée")

    if user_id == request.siem_user['id']:
        messages.error(request, "Vous ne pouvez pas désactiver votre propre compte")
        return redirect('users_list')

    user = db.get_user_by_id(user_id)
    if not user:
        return redirect('users_list')

    new_state = not user['is_active']
    db.update_user_active(user_id, new_state)

    db.log_audit(
        user_id=request.siem_user['id'],
        user_email=request.siem_user['email'],
        action='USER_ACTIVATED' if new_state else 'USER_DEACTIVATED',
        action_category='USER',
        target_table='users',
        target_id=user_id,
        ip_address=_get_client_ip(request),
    )
    messages.success(request, f"Utilisateur {'activé' if new_state else 'désactivé'}")
    return redirect('users_list')


@require_POST
@csrf_protect
def user_delete(request, user_id):
    if not has_permission(request.siem_user, 'users.delete'):
        return HttpResponseForbidden("Permission refusée")

    if user_id == request.siem_user['id']:
        messages.error(request, "Vous ne pouvez pas supprimer votre propre compte")
        return redirect('users_list')

    db.soft_delete_user(user_id)
    db.log_audit(
        user_id=request.siem_user['id'],
        user_email=request.siem_user['email'],
        action='USER_DELETED',
        action_category='USER',
        target_table='users',
        target_id=user_id,
        ip_address=_get_client_ip(request),
    )
    messages.success(request, "Utilisateur supprimé")
    return redirect('users_list')


# ============================================================================
# SETTINGS
# ============================================================================

def settings_view(request):
    if not has_permission(request.siem_user, 'settings.read'):
        return HttpResponseForbidden("Permission refusée")

    if request.method == 'POST':
        if not has_permission(request.siem_user, 'settings.update'):
            return HttpResponseForbidden("Permission refusée")

        for key, value in request.POST.items():
            if key == 'csrfmiddlewaretoken':
                continue
            db.update_setting(key, value, request.siem_user['id'])

        db.log_audit(
            user_id=request.siem_user['id'],
            user_email=request.siem_user['email'],
            action='SETTINGS_UPDATED',
            action_category='CONFIG',
            ip_address=_get_client_ip(request),
        )
        messages.success(request, "Paramètres mis à jour. L'agent rechargera la config au prochain cycle.")
        return redirect('settings')

    settings_grouped = db.list_settings()
    return render(request, 'settings.html', {'settings_grouped': settings_grouped})


# ============================================================================
# IA - CHAT + RÉSUMÉ + SUGGESTIONS
# ============================================================================

def ai_view(request):
    """Page principale de l'assistant IA."""
    available, status_msg = ai.is_available()
    return render(request, 'ai.html', {
        'available': available,
        'status_msg': status_msg,
    })


@require_POST
@csrf_protect
def ai_chat(request):
    """Endpoint AJAX pour le chatbot."""
    available, _ = ai.is_available()
    if not available:
        return JsonResponse({'error': "IA non disponible"}, status=503)

    question = request.POST.get('question', '').strip()
    if not question or len(question) > 1000:
        return JsonResponse({'error': "Question invalide"}, status=400)

    # Contexte : derniers events si l'utilisateur parle d'alertes
    context_alerts = None
    if any(w in question.lower() for w in ['alerte', 'alert', 'critique', 'critical', 'récent', 'recent']):
        context_alerts = db.list_alerts(limit=20)

    answer = ai.chat(question, context_alerts=context_alerts)

    db.log_audit(
        user_id=request.siem_user['id'],
        user_email=request.siem_user['email'],
        action='AI_CHAT',
        action_category='AI',
        details=question[:500],
        ip_address=_get_client_ip(request),
    )

    return JsonResponse({
        'question': question,
        'answer': answer or "Désolé, je n'ai pas pu générer de réponse. Vérifiez qu'Ollama est lancé.",
    })


def ai_summary(request):
    """Génère un résumé exécutif."""
    available, msg = ai.is_available()
    if not available:
        return JsonResponse({'error': msg}, status=503)

    summary = ai.executive_summary()
    return JsonResponse({
        'summary': summary or "Impossible de générer le résumé."
    })


def ai_suggest_filters(request):
    """Suggère des filtres FP basés sur l'historique."""
    available, msg = ai.is_available()
    if not available:
        return JsonResponse({'error': msg}, status=503)

    suggestion = ai.suggest_fp_filters()
    return JsonResponse({
        'suggestion': suggestion or "Aucune suggestion."
    })


def ai_explain(request, alert_id):
    """Explique une alerte (avec cache)."""
    available, msg = ai.is_available()
    if not available:
        return JsonResponse({'error': msg}, status=503)

    result = ai.explain_alert(alert_id)
    if not result:
        return JsonResponse({'error': "Échec génération"}, status=500)

    return JsonResponse(result)


# ============================================================================
# CHARTS - API JSON pour Chart.js
# ============================================================================

def chart_timeline(request):
    days = int(request.GET.get('days', 7))
    days = max(1, min(days, 90))
    rows = db.alerts_timeline(days=days)
    return JsonResponse({'data': rows})


def chart_hourly(request):
    rows = db.alerts_by_hour_24h()
    return JsonResponse({'data': rows})


def chart_categories(request):
    rows = db.category_distribution()
    return JsonResponse({'data': rows})


# ============================================================================
# EXPORT CSV
# ============================================================================

def export_alerts_csv(request):
    import csv
    from django.http import HttpResponse

    severity = request.GET.get('severity') or None
    status = request.GET.get('status') or None
    days = int(request.GET.get('days', 30))
    days = max(1, min(days, 365))

    rows = db.alerts_for_export(severity=severity, status=status, days=days)

    response = HttpResponse(content_type='text/csv; charset=utf-8')
    filename = f"siem-africa-alerts-{datetime_now_str()}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    response.write('\ufeff')  # BOM UTF-8 pour Excel

    writer = csv.writer(response, delimiter=';')
    writer.writerow([
        'ID', 'UUID', 'Sévérité', 'Statut', 'Confiance',
        'Titre', 'IP source', 'IP destination', 'Hits',
        'Première vue', 'Dernière vue', 'Créée', 'Résolue',
        'Signature ID', 'Signature', 'Source',
        'Catégorie', 'MITRE Technique', 'MITRE Nom'
    ])

    for r in rows:
        writer.writerow([
            r.get('id'), r.get('alert_uuid'), r.get('severity'), r.get('status'),
            r.get('confidence'), r.get('title'), r.get('src_ip'), r.get('dst_ip'),
            r.get('event_count'),
            r.get('first_seen'), r.get('last_seen'), r.get('created_at'),
            r.get('resolved_at'),
            r.get('signature_id'), r.get('sig_name'), r.get('sig_source'),
            r.get('category'), r.get('mitre_tech'), r.get('mitre_name'),
        ])

    db.log_audit(
        user_id=request.siem_user['id'],
        user_email=request.siem_user['email'],
        action='ALERTS_EXPORTED_CSV',
        action_category='ALERT',
        details=f"{len(rows)} alertes exportées",
        ip_address=_get_client_ip(request),
    )

    return response


def datetime_now_str():
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d-%H%M%S")
