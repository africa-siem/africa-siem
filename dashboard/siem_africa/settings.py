"""
SIEM Africa - Django settings
La BDD principale est /var/lib/siem-africa/siem.db (Module 2).
Django utilise UNIQUEMENT cette BDD via raw queries (pas de migrate).
"""
from pathlib import Path
import os
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent

# Charger .env si présent
ENV_FILE = '/etc/siem-africa/dashboard.env'
ENV = {}
if os.path.exists(ENV_FILE):
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            ENV[k.strip()] = v.strip().strip('"').strip("'")

# SECRET KEY (généré à l'install et stocké dans dashboard.env)
SECRET_KEY = ENV.get('SECRET_KEY', secrets.token_urlsafe(50))

DEBUG = ENV.get('DEBUG', '0') == '1'

ALLOWED_HOSTS = ['*']  # Restriction par firewall plutôt qu'ici

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'core.middleware.SiemAuthMiddleware',
]

ROOT_URLCONF = 'siem_africa.urls'

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'templates'],
    'APP_DIRS': True,
    'OPTIONS': {
        'context_processors': [
            'django.template.context_processors.request',
            'django.contrib.auth.context_processors.auth',
            'django.contrib.messages.context_processors.messages',
            'core.context.siem_context',
        ],
    },
}]

WSGI_APPLICATION = 'siem_africa.wsgi.application'

# BDD Django minimale (sessions). Les vraies données sont dans SIEM_DB_PATH.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/var/lib/siem-africa/dashboard_sessions.db',
    }
}

# Chemin vers la BDD principale SIEM Africa (Module 2)
SIEM_DB_PATH = ENV.get('DB_PATH', '/var/lib/siem-africa/siem.db')

LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Africa/Douala'
USE_I18N = True
USE_TZ = False

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Sessions
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_SECURE = False  # HTTPS plus tard
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 8 * 3600  # 8h

# Login
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} [{levelname}] {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/siem-africa/dashboard.log',
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}
