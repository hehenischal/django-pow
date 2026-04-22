"""
ProofOfWorkMiddleware — enforces PoW on configured paths/methods.
"""

import json
import logging

from django.http import JsonResponse

from . import settings as pow_settings
from .pow import get_challenge_for_request, get_difficulty, rotate_challenge, verify_proof_of_work

logger = logging.getLogger(__name__)


class ProofOfWorkMiddleware:
    """
    Middleware that enforces Proof of Work on configured URL paths.

    Configuration (all via ``DJANGO_POW`` in settings.py):

    - ``PROTECTED_PATHS``     — list of URL paths to protect.
    - ``PROTECTED_METHODS``   — HTTP methods to check (default: ``["POST"]``).
    - ``PATH_DIFFICULTIES``   — per-path difficulty overrides.
    - ``DEFAULT_DIFFICULTY``  — fallback difficulty.
    - ``NONCE_HEADER``        — META key for the nonce header.
    - ``USERNAME_FIELD``      — POST/JSON field name for the identity.
    - ``SKIP_FOR_AUTHENTICATED`` — skip check for logged-in users.
    - ``ERROR_STATUS_CODE``   — response code on failure (default: 403).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_protected(request) -> bool:
        cfg = pow_settings.get_settings()
        return (
            request.method in cfg["PROTECTED_METHODS"]
            and request.path in cfg["PROTECTED_PATHS"]
        )

    @staticmethod
    def _extract_username(request) -> str | None:
        """Try POST data first, then JSON body."""
        field = pow_settings.get("USERNAME_FIELD")
        if request.method == "POST":
            value = request.POST.get(field)
            if value:
                return value
        # JSON body fallback
        content_type = request.content_type or ""
        if "application/json" in content_type:
            try:
                body = json.loads(request.body)
                return body.get(field)
            except (json.JSONDecodeError, AttributeError):
                pass
        return None

    @staticmethod
    def _error(message: str, status: int | None = None) -> JsonResponse:
        status = status or pow_settings.get("ERROR_STATUS_CODE")
        return JsonResponse({"error": message, "pow_required": True}, status=status)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def __call__(self, request):
        if self._is_protected(request):
            response = self._enforce_pow(request)
            if response is not None:
                return response

        return self.get_response(request)

    def _enforce_pow(self, request):
        """
        Returns a JsonResponse error if PoW fails, or None to continue.
        """
        cfg = pow_settings.get_settings()

        # Optional: skip for authenticated users
        if cfg["SKIP_FOR_AUTHENTICATED"] and getattr(request, "user", None) and request.user.is_authenticated:
            return None

        nonce = request.META.get(cfg["NONCE_HEADER"])
        challenge = request.session.get(cfg["CHALLENGE_SESSION_KEY"])
        username = self._extract_username(request)

        # ---- parameter presence checks ----
        if not nonce:
            logger.warning("PoW rejected [%s]: missing nonce header", request.path)
            return self._error("Proof of Work nonce is missing (X-PoW-Nonce header required).")

        if not challenge:
            logger.warning("PoW rejected [%s]: no challenge in session", request.path)
            return self._error("No PoW challenge found in session. Request a fresh challenge first.")

        if not username:
            logger.warning("PoW rejected [%s]: missing username field", request.path)
            return self._error(
                f"Identity field '{cfg['USERNAME_FIELD']}' is missing from the request."
            )

        # ---- verification ----
        difficulty = get_difficulty(request.path)
        valid, result_hash = verify_proof_of_work(
            challenge=challenge,
            username=username,
            nonce=nonce,
            difficulty=difficulty,
            algorithm=cfg["HASH_ALGORITHM"],
        )

        logger.debug(
            "PoW check path=%s user=%s nonce=%s difficulty=%d hash=%s valid=%s",
            request.path, username, nonce, difficulty, result_hash, valid,
        )

        if not valid:
            logger.warning(
                "PoW failed [%s] user=%s difficulty=%d hash=%s",
                request.path, username, difficulty, result_hash,
            )
            return self._error("Proof of Work verification failed. Please retry.")

        # ---- success: rotate challenge to prevent replay ----
        rotate_challenge(request)
        logger.info("PoW passed [%s] user=%s difficulty=%d", request.path, username, difficulty)
        return None
