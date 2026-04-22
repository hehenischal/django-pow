"""
View decorators for per-view Proof of Work enforcement.

Usage::

    from django_pow.decorators import require_pow

    @require_pow(difficulty=5)
    def my_view(request):
        ...

Or use the class-based mixin::

    from django_pow.decorators import ProofOfWorkMixin

    class RegisterView(ProofOfWorkMixin, CreateView):
        pow_difficulty = 5
"""

import functools
import json
import logging

from django.http import JsonResponse

from . import settings as pow_settings
from .pow import get_challenge_for_request, get_difficulty, rotate_challenge, verify_proof_of_work

logger = logging.getLogger(__name__)


def _extract_username(request):
    field = pow_settings.get("USERNAME_FIELD")
    if request.method == "POST":
        value = request.POST.get(field)
        if value:
            return value
    content_type = request.content_type or ""
    if "application/json" in content_type:
        try:
            return json.loads(request.body).get(field)
        except (json.JSONDecodeError, AttributeError):
            pass
    return None


def _pow_error(message, status=None):
    status = status or pow_settings.get("ERROR_STATUS_CODE")
    return JsonResponse({"error": message, "pow_required": True}, status=status)


def require_pow(difficulty=None, methods=None, username_field=None):
    """
    Decorator that enforces Proof of Work on a view function.

    Args:
        difficulty:     Override the required difficulty for this view.
        methods:        HTTP methods to enforce (default: ``["POST"]``).
        username_field: Override the identity field name.

    Example::

        @require_pow(difficulty=5)
        def register(request):
            ...
    """
    if methods is None:
        methods = pow_settings.get("PROTECTED_METHODS")

    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.method not in methods:
                return view_func(request, *args, **kwargs)

            cfg = pow_settings.get_settings()

            # Skip for authenticated users if configured
            if cfg["SKIP_FOR_AUTHENTICATED"] and getattr(request, "user", None) and request.user.is_authenticated:
                return view_func(request, *args, **kwargs)

            nonce = request.META.get(cfg["NONCE_HEADER"])
            challenge = request.session.get(cfg["CHALLENGE_SESSION_KEY"])
            field = username_field or cfg["USERNAME_FIELD"]

            # Pull username using the (possibly overridden) field name
            username = request.POST.get(field)
            if not username and "application/json" in (request.content_type or ""):
                try:
                    username = json.loads(request.body).get(field)
                except (json.JSONDecodeError, AttributeError):
                    pass

            if not nonce:
                return _pow_error("Proof of Work nonce is missing (X-PoW-Nonce header required).")
            if not challenge:
                return _pow_error("No PoW challenge found in session.")
            if not username:
                return _pow_error(f"Identity field '{field}' is missing.")

            diff = difficulty if difficulty is not None else get_difficulty(request.path)
            valid, result_hash = verify_proof_of_work(
                challenge=challenge,
                username=username,
                nonce=nonce,
                difficulty=diff,
                algorithm=cfg["HASH_ALGORITHM"],
            )

            logger.debug(
                "PoW decorator check view=%s user=%s difficulty=%d hash=%s valid=%s",
                view_func.__name__, username, diff, result_hash, valid,
            )

            if not valid:
                return _pow_error("Proof of Work verification failed. Please retry.")

            rotate_challenge(request)
            return view_func(request, *args, **kwargs)

        return wrapper
    return decorator


class ProofOfWorkMixin:
    """
    Class-based view mixin that enforces PoW on ``POST`` (and any methods
    listed in ``pow_methods``).

    Attributes:
        pow_difficulty (int | None): Override difficulty; None uses settings default.
        pow_methods (list[str]):     Methods to enforce; defaults to ``["POST"]``.
        pow_username_field (str | None): Override username field name.

    Example::

        class RegisterView(ProofOfWorkMixin, CreateView):
            pow_difficulty = 5
            template_name = "register.html"
    """

    pow_difficulty: int | None = None
    pow_methods: list[str] | None = None
    pow_username_field: str | None = None

    def dispatch(self, request, *args, **kwargs):
        methods = self.pow_methods or pow_settings.get("PROTECTED_METHODS")
        if request.method in methods:
            error_response = self._check_pow(request)
            if error_response is not None:
                return error_response
        return super().dispatch(request, *args, **kwargs)

    def _check_pow(self, request):
        cfg = pow_settings.get_settings()

        if cfg["SKIP_FOR_AUTHENTICATED"] and getattr(request, "user", None) and request.user.is_authenticated:
            return None

        nonce = request.META.get(cfg["NONCE_HEADER"])
        challenge = request.session.get(cfg["CHALLENGE_SESSION_KEY"])
        field = self.pow_username_field or cfg["USERNAME_FIELD"]
        username = request.POST.get(field)
        if not username and "application/json" in (request.content_type or ""):
            try:
                username = json.loads(request.body).get(field)
            except (json.JSONDecodeError, AttributeError):
                pass

        if not nonce:
            return _pow_error("Proof of Work nonce is missing.")
        if not challenge:
            return _pow_error("No PoW challenge found in session.")
        if not username:
            return _pow_error(f"Identity field '{field}' is missing.")

        diff = self.pow_difficulty if self.pow_difficulty is not None else get_difficulty(request.path)
        valid, _ = verify_proof_of_work(
            challenge=challenge,
            username=username,
            nonce=nonce,
            difficulty=diff,
            algorithm=cfg["HASH_ALGORITHM"],
        )

        if not valid:
            return _pow_error("Proof of Work verification failed.")

        rotate_challenge(request)
        return None
