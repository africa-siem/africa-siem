"""
Middleware d'authentification SIEM Africa.

Place l'utilisateur courant dans request.siem_user à partir de la session.
"""
import logging
from django.shortcuts import redirect
from django.urls import reverse, resolve

from core import db

log = logging.getLogger("siem-dashboard.middleware")

# URLs accessibles sans login
PUBLIC_URLS = {'login', 'logout', 'static'}


class SiemAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.siem_user = None

        # Récupérer l'user depuis la session
        user_id = request.session.get('siem_user_id')
        if user_id:
            user = db.get_user_by_id(user_id)
            if user:
                request.siem_user = user
            else:
                # User désactivé ou supprimé
                request.session.flush()

        # Vérifier si l'URL nécessite un login
        try:
            url_name = resolve(request.path_info).url_name
        except Exception:
            url_name = None

        # Static files / admin
        if request.path_info.startswith('/static/'):
            return self.get_response(request)

        # Login required
        if url_name not in PUBLIC_URLS and request.siem_user is None:
            if request.method == 'GET':
                return redirect(f"{reverse('login')}?next={request.path}")
            else:
                return redirect('login')

        return self.get_response(request)
