"""SIEM Africa - URL routing"""
from django.urls import path
from core import views


urlpatterns = [
    # Auth
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('password/change/', views.change_password_view, name='change_password'),

    # Home
    path('', views.home_view, name='home'),

    # Alertes
    path('alerts/', views.alerts_list, name='alerts_list'),
    path('alerts/<int:alert_id>/', views.alert_detail, name='alert_detail'),
    path('alerts/<int:alert_id>/action/', views.alert_action, name='alert_action'),
    path('alerts/export.csv', views.export_alerts_csv, name='export_alerts_csv'),

    # Filtres FP
    path('filters/', views.filters_list, name='filters_list'),
    path('filters/new/', views.filter_create, name='filter_create'),
    path('filters/<int:filter_id>/delete/', views.filter_delete, name='filter_delete'),
    path('api/signatures/search/', views.filter_signature_search, name='signature_search'),

    # IPs bloquées
    path('blocked-ips/', views.blocked_ips_list, name='blocked_ips_list'),
    path('blocked-ips/<int:ip_id>/unblock/', views.unblock_ip, name='unblock_ip'),

    # MITRE
    path('mitre/', views.mitre_matrix, name='mitre_matrix'),
    path('mitre/<str:technique_id>/', views.mitre_technique_detail, name='mitre_detail'),

    # Honeypot
    path('honeypot/', views.honeypot_view, name='honeypot'),

    # Users / RBAC
    path('users/', views.users_list, name='users_list'),
    path('users/new/', views.user_create, name='user_create'),
    path('users/<int:user_id>/toggle/', views.user_toggle_active, name='user_toggle'),
    path('users/<int:user_id>/delete/', views.user_delete, name='user_delete'),

    # Settings
    path('settings/', views.settings_view, name='settings'),

    # IA
    path('ai/', views.ai_view, name='ai'),
    path('ai/chat/', views.ai_chat, name='ai_chat'),
    path('ai/summary/', views.ai_summary, name='ai_summary'),
    path('ai/suggest-filters/', views.ai_suggest_filters, name='ai_suggest_filters'),
    path('ai/explain/<int:alert_id>/', views.ai_explain, name='ai_explain'),

    # Charts API JSON
    path('api/charts/timeline/', views.chart_timeline, name='chart_timeline'),
    path('api/charts/hourly/', views.chart_hourly, name='chart_hourly'),
    path('api/charts/categories/', views.chart_categories, name='chart_categories'),

    # Health
    path('health/', views.health, name='health'),
]
