"""
Authentification SIEM Africa.

Le Module 2 utilise argon2id pour les mots de passe (champ password_hash).
Le dashboard supporte argon2id, bcrypt, et pbkdf2.
"""
import hashlib
import secrets
import logging

log = logging.getLogger("siem-dashboard.auth")


def verify_password(password_plain, password_hash):
    """
    Vérifie un mot de passe contre son hash.
    Supporte argon2id (préfixe $argon2id$), bcrypt ($2a$, $2b$), pbkdf2.
    """
    if not password_plain or not password_hash:
        return False

    # argon2id (Module 2 par défaut)
    if password_hash.startswith('$argon2'):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError
            ph = PasswordHasher()
            try:
                ph.verify(password_hash, password_plain)
                return True
            except VerifyMismatchError:
                return False
            except Exception as e:
                log.error(f"Erreur argon2 : {e}")
                return False
        except ImportError:
            log.error("argon2-cffi non installé. pip install argon2-cffi")
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
            log.error("bcrypt non installé.")
            return False
        except Exception as e:
            log.error(f"Erreur bcrypt : {e}")
            return False

    # pbkdf2 (fallback)
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

    log.warning(f"Hash format inconnu : {password_hash[:10]}...")
    return False


def hash_password(password_plain):
    """
    Hash un mot de passe.
    Préfère argon2id (compatible Module 2), fallback bcrypt, puis pbkdf2.
    """
    # Argon2 d'abord (Module 2 utilise ça)
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        return ph.hash(password_plain)
    except ImportError:
        pass

    # bcrypt fallback
    try:
        import bcrypt
        return bcrypt.hashpw(
            password_plain.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')
    except ImportError:
        pass

    # pbkdf2 dernier recours
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

    Format permissions accepté (table roles.permissions) :
    - JSON liste : ["alerts.read", "users.create", ...]
    - JSON string "*" : tout (super admin)
    - JSON dict : {"*": true} ou {"alerts": ["read", "update"], ...}

    Pour les ADMIN, on autorise TOUJOURS tout (sécurité par défaut).
    """
    if not user:
        return False

    # ADMIN a TOUJOURS tous les droits, peu importe le format du JSON
    role_code = (user.get("role_code") or "").upper()
    if role_code == "ADMIN":
        return True

    # Sinon vérifier le JSON permissions
    perms_raw = user.get("role_permissions") or "[]"

    try:
        import json
        if isinstance(perms_raw, str):
            perms_data = json.loads(perms_raw)
        else:
            perms_data = perms_raw

        # Format 1 : "*" (string)
        if perms_data == "*":
            return True

        # Format 2 : liste plate ["perm1", "perm2"]
        if isinstance(perms_data, list):
            if "*" in perms_data:
                return True
            return permission_code in perms_data

        # Format 3 : dict {"resource": ["read", "write"]} ou {"*": true}
        if isinstance(perms_data, dict):
            if perms_data.get("*"):
                return True
            # Décomposer permission_code en "resource.action"
            if "." in permission_code:
                resource, action = permission_code.split(".", 1)
                resource_perms = perms_data.get(resource)
                if resource_perms == "*" or resource_perms is True:
                    return True
                if isinstance(resource_perms, list):
                    return action in resource_perms or "*" in resource_perms
            return False

        return False
    except (ValueError, TypeError) as e:
        log.warning(f"Erreur parsing permissions pour role {role_code} : {e}")
        # Fail-closed sauf pour admin (déjà géré au-dessus)
        return False
