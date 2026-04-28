"""Context processors Django."""
from core import db


def siem_context(request):
    ctx = {
        'siem_user': getattr(request, 'siem_user', None),
        'unread_notifications': 0,
    }

    if ctx['siem_user']:
        try:
            ctx['unread_notifications'] = db.count_unread_notifications(
                ctx['siem_user']['id']
            )
        except Exception:
            pass

    return ctx
