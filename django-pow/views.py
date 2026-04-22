"""
Built-in views for Django-POW.

Include the package URLs to get the challenge endpoint automatically::

    # urls.py
    urlpatterns = [
        path("pow/", include("django_pow.urls")),
        ...
    ]

This provides:
    GET  /pow/challenge/   →  returns { challenge, difficulty }
    GET  /pow/difficulty/  →  returns { path, difficulty }  (query param: ?path=/register/)
"""

from django.http import JsonResponse
from django.views import View
from django.views.decorators.http import require_GET

from . import settings as pow_settings
from .pow import generate_challenge, get_challenge_for_request, get_difficulty


class ChallengeView(View):
    """
    Issue or refresh a PoW challenge for the current session.

    ``GET``  — return the current (or newly created) challenge + difficulty.
    ``POST`` — force-rotate the challenge and return a fresh one.

    Query parameters:
        path (str): URL path to look up per-path difficulty, e.g. ``?path=/register/``
    """

    def get(self, request):
        path = request.GET.get("path")
        challenge = get_challenge_for_request(request)
        difficulty = get_difficulty(path)
        return JsonResponse({
            "challenge": challenge,
            "difficulty": difficulty,
            "algorithm": pow_settings.get("HASH_ALGORITHM"),
        })

    def post(self, request):
        """Force-rotate — useful when the user wants to start over."""
        from .pow import rotate_challenge
        path = request.POST.get("path") or request.GET.get("path")
        challenge = rotate_challenge(request)
        difficulty = get_difficulty(path)
        return JsonResponse({
            "challenge": challenge,
            "difficulty": difficulty,
            "algorithm": pow_settings.get("HASH_ALGORITHM"),
            "rotated": True,
        })


@require_GET
def difficulty_view(request):
    """
    Return the difficulty for a given path.

    Query parameter:
        path (str): The URL path to check, e.g. ``?path=/register/``
    """
    path = request.GET.get("path")
    difficulty = get_difficulty(path)
    return JsonResponse({
        "path": path or "(default)",
        "difficulty": difficulty,
    })
