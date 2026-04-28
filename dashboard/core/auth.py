"""
Authentification SIEM Africa.

Le Module 2 utilise bcrypt pour les mots de passe (champ password_hash).
On utilise passlib avec bcrypt pour vérifier — sinon fallback hashlib.
"""
import hashlib
import secrets
import logging

log = logging.getLogger("siem-dashboard.auth")


def verify_password(password_plain, password_hash):
    """
    Vérifie un mot de passe contre son hash.
    Supporte bcrypt (préfixe $2a$ / $2b$) ou pbkdf2 (fallback).
    """
    if not password_plain or not password_hash:
        return False

    # bcrypt
    if password_hash.startswith(('$2a$', '$2b$', '$2y$')):
        try:
            import bcrypt
            return bcrypt.checkpw(
                password_plain.encode('utf-8'),
                password_hash.encode('utf-8')
            )
        except ImportError:
            log.error("bcrypt non installé. pip3 install bcrypt")
            return False
        except Exception as e:
            log.error(f"Erreur bcrypt : {e}")
            return False

    # pbkdf2 (fallback custom : pbkdf2$<salt>$<hash>)
    if password_hash.startswith('pbkdf2$'):
        try:
            _, salt, hash_hex = password_hash.split('$', 2)
            computed = hashlib.pbkdf2_hmac(
                'sha256',
                password_plain.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            ).hex()
            return secrets.compare_digest(computed, hash_hex)
        except Exception:
            return False

    return False


def hash_password(password_plain):
    """Hash un mot de passe avec bcrypt (preferred) ou pbkdf2."""
    try:
        import bcrypt
        return bcrypt.hashpw(
            password_plain.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')
    except ImportError:
        # Fallback pbkdf2
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac(
            'sha256',
            password_plain.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return f"pbkdf2${salt}${h}"


def has_permission(user, permission_code):
    """
    Vérifie qu'un user a une permission.
    user["role_permissions"] est une chaîne JSON ['perm1', 'perm2', ...] ou '*' (admin).
    """
    if not user:
        return False

    perms = user.get("role_permissions") or "[]"
    try:
        import json
        perms_list = json.loads(perms) if isinstance(perms, str) else perms
        if "*" in perms_list:
            return True
        return permission_code in perms_list
    except (ValueError, TypeError):
        return False
