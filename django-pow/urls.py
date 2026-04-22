"""
URL patterns for Django-POW built-in views.

Include in your project urls.py::

    path("pow/", include("django_pow.urls")),

Endpoints:
    GET  /pow/challenge/          → issue / return session challenge
    POST /pow/challenge/          → force-rotate challenge
    GET  /pow/challenge/?path=X   → challenge + difficulty for path X
    GET  /pow/difficulty/?path=X  → difficulty for path X
"""

from django.urls import path

from .views import ChallengeView, difficulty_view

app_name = "django_pow"

urlpatterns = [
    path("challenge/", ChallengeView.as_view(), name="challenge"),
    path("difficulty/", difficulty_view, name="difficulty"),
]
