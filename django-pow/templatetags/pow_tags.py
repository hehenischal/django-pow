"""
Template tags for Django-POW.

Load in templates::

    {% load pow_tags %}

Tags:
    {% pow_challenge_data %}          — render a <script> block with challenge JSON
    {% pow_challenge_data path="/register/" %}
    {% pow_worker_script %}           — render the Web Worker inline or as a <script src=>
"""

from django import template
from django.utils.safestring import mark_safe

from django_pow import settings as pow_settings
from django_pow.pow import get_challenge_for_request, get_difficulty

register = template.Library()


@register.simple_tag(takes_context=True)
def pow_challenge_data(context, path=None):
    """
    Render a ``<script>`` block exposing the current challenge as
    ``window.POW_CONFIG``.

    Usage::

        {% load pow_tags %}
        {% pow_challenge_data path="/register/" %}
    """
    request = context.get("request")
    if request is None:
        return ""

    challenge = get_challenge_for_request(request)
    difficulty = get_difficulty(path or request.path)
    algorithm = pow_settings.get("HASH_ALGORITHM")

    script = (
        "<script>"
        f'window.POW_CONFIG = {{"challenge": "{challenge}", '
        f'"difficulty": {difficulty}, '
        f'"algorithm": "{algorithm}"}};\n'
        "</script>"
    )
    return mark_safe(script)


@register.simple_tag
def pow_difficulty(path=None):
    """Return the integer difficulty for a path (usable in templates)."""
    return get_difficulty(path)
