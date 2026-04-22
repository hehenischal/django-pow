"""
Django-POW settings with sensible defaults.

In your Django settings.py, override via:

    DJANGO_POW = {
        "DEFAULT_DIFFICULTY": 4,
        "CHALLENGE_LENGTH": 16,
        "CHALLENGE_SESSION_KEY": "pow_challenge",
        "NONCE_HEADER": "HTTP_X_POW_NONCE",
        "USERNAME_FIELD": "username",
        "PATH_DIFFICULTIES": {
            "/register/": 5,
            "/login/": 3,
        },
        "PROTECTED_PATHS": ["/register/", "/login/"],
        "PROTECTED_METHODS": ["POST"],
        "ERROR_STATUS_CODE": 403,
    }
"""

from django.conf import settings

DEFAULTS = {
    # Number of leading zeros required in the hash
    "DEFAULT_DIFFICULTY": 4,
    # Byte length of the random challenge string
    "CHALLENGE_LENGTH": 16,
    # Session key used to store the challenge
    "CHALLENGE_SESSION_KEY": "pow_challenge",
    # HTTP header name (Django META format) carrying the nonce
    "NONCE_HEADER": "HTTP_X_POW_NONCE",
    # POST field (or JSON key) for the username/identity used in hashing
    "USERNAME_FIELD": "username",
    # Per-path difficulty overrides  {"/path/": difficulty_int}
    "PATH_DIFFICULTIES": {},
    # Paths that the middleware will enforce PoW on
    "PROTECTED_PATHS": [],
    # HTTP methods to enforce (defaults to POST only)
    "PROTECTED_METHODS": ["POST"],
    # HTTP status code returned on failure
    "ERROR_STATUS_CODE": 403,
    # If True, skip PoW for authenticated users
    "SKIP_FOR_AUTHENTICATED": False,
    # Hash algorithm: "sha256" | "sha512" | "md5"
    "HASH_ALGORITHM": "sha256",
}


def get_settings():
    """Return merged settings dict (user overrides on top of DEFAULTS)."""
    user = getattr(settings, "DJANGO_POW", {})
    return {**DEFAULTS, **user}


def get(key):
    """Convenience accessor: get a single setting value."""
    return get_settings()[key]
