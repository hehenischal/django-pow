"""
Tests for Django-POW.

Run with: python -m pytest tests/ -v
or:        python manage.py test django_pow
"""

import hashlib
import json
from unittest.mock import patch

import pytest
from django.test import RequestFactory, TestCase, override_settings
from django.test.client import Client

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

POW_SETTINGS_BASE = {
    "DEFAULT_DIFFICULTY": 2,
    "CHALLENGE_LENGTH": 8,
    "CHALLENGE_SESSION_KEY": "pow_challenge",
    "NONCE_HEADER": "HTTP_X_POW_NONCE",
    "USERNAME_FIELD": "username",
    "PATH_DIFFICULTIES": {},
    "PROTECTED_PATHS": ["/register/"],
    "PROTECTED_METHODS": ["POST"],
    "ERROR_STATUS_CODE": 403,
    "SKIP_FOR_AUTHENTICATED": False,
    "HASH_ALGORITHM": "sha256",
}


def _find_nonce(challenge: str, username: str, difficulty: int = 2) -> str:
    """Brute-force a valid nonce (fast at low difficulty)."""
    prefix = "0" * difficulty
    nonce = 0
    while True:
        content = f"{challenge}{username}{nonce}".encode()
        h = hashlib.sha256(content).hexdigest()
        if h.startswith(prefix):
            return str(nonce)
        nonce += 1


# ---------------------------------------------------------------------------
# Core PoW logic
# ---------------------------------------------------------------------------

class TestPowCore(TestCase):

    def test_generate_challenge_default_length(self):
        from django_pow.pow import generate_challenge
        # test settings use CHALLENGE_LENGTH=8 → 16 hex chars
        c = generate_challenge()
        self.assertEqual(len(c), 16)

    def test_generate_challenge_custom_length(self):
        from django_pow.pow import generate_challenge
        c = generate_challenge(length=4)
        self.assertEqual(len(c), 8)

    def test_generate_challenge_uniqueness(self):
        from django_pow.pow import generate_challenge
        challenges = {generate_challenge() for _ in range(20)}
        self.assertEqual(len(challenges), 20)

    def test_compute_hash_sha256(self):
        from django_pow.pow import compute_hash
        h = compute_hash("abc", "user", 42, algorithm="sha256")
        expected = hashlib.sha256(b"abcuser42").hexdigest()
        self.assertEqual(h, expected)

    def test_compute_hash_sha512(self):
        from django_pow.pow import compute_hash
        h = compute_hash("abc", "user", 42, algorithm="sha512")
        expected = hashlib.sha512(b"abcuser42").hexdigest()
        self.assertEqual(h, expected)

    def test_compute_hash_unsupported_algo(self):
        from django_pow.pow import compute_hash
        with self.assertRaises(ValueError):
            compute_hash("abc", "user", 42, algorithm="blake2b")

    def test_verify_valid_nonce(self):
        from django_pow.pow import verify_proof_of_work
        challenge = "testchallenge"
        username = "alice"
        nonce = _find_nonce(challenge, username, difficulty=2)
        valid, h = verify_proof_of_work(challenge, username, nonce, difficulty=2)
        self.assertTrue(valid)
        self.assertTrue(h.startswith("00"))

    def test_verify_invalid_nonce(self):
        from django_pow.pow import verify_proof_of_work
        valid, _ = verify_proof_of_work("challenge", "user", "0", difficulty=10)
        self.assertFalse(valid)

    @override_settings(DJANGO_POW={})
    def test_get_difficulty_default(self):
        from django_pow.pow import get_difficulty
        self.assertEqual(get_difficulty(), 4)  # from module DEFAULTS

    @override_settings(DJANGO_POW={**POW_SETTINGS_BASE, "PATH_DIFFICULTIES": {"/register/": 5}})
    def test_get_difficulty_path_override(self):
        from django_pow import settings as s
        import importlib
        from django_pow import pow as pow_mod
        importlib.reload(s)
        importlib.reload(pow_mod)
        from django_pow.pow import get_difficulty
        self.assertEqual(get_difficulty("/register/"), 5)

    def test_rotate_challenge(self):
        from django.test import RequestFactory
        from django_pow.pow import get_challenge_for_request, rotate_challenge
        factory = RequestFactory()
        request = factory.get("/")
        request.session = {}
        c1 = get_challenge_for_request(request)
        c2 = rotate_challenge(request)
        self.assertNotEqual(c1, c2)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

@override_settings(DJANGO_POW=POW_SETTINGS_BASE)
class TestMiddleware(TestCase):

    def setUp(self):
        from django_pow.middleware import ProofOfWorkMiddleware
        self.factory = RequestFactory()
        self.middleware = ProofOfWorkMiddleware(lambda r: __import__("django.http", fromlist=["HttpResponse"]).HttpResponse("OK"))

    def _make_post(self, path, username, nonce=None, challenge=None):
        request = self.factory.post(path, data={"username": username})
        request.session = {}
        if challenge:
            request.session["pow_challenge"] = challenge
        if nonce:
            request.META["HTTP_X_POW_NONCE"] = nonce
        return request

    def test_unprotected_path_passes(self):
        request = self.factory.post("/login/", data={"username": "alice"})
        request.session = {}
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_missing_nonce_returns_403(self):
        request = self._make_post("/register/", "alice", challenge="abc")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)
        body = json.loads(response.content)
        self.assertIn("nonce", body["error"].lower())

    def test_missing_challenge_returns_403(self):
        request = self._make_post("/register/", "alice", nonce="0")
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_missing_username_returns_403(self):
        request = self.factory.post("/register/", data={})
        request.session = {"pow_challenge": "abc"}
        request.META["HTTP_X_POW_NONCE"] = "0"
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)

    def test_invalid_nonce_returns_403(self):
        challenge = "testchallenge"
        request = self._make_post("/register/", "alice", nonce="99999999", challenge=challenge)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)
        body = json.loads(response.content)
        self.assertIn("error", body)

    def test_valid_nonce_passes(self):
        challenge = "testchallenge"
        username = "alice"
        nonce = _find_nonce(challenge, username, difficulty=2)
        request = self._make_post("/register/", username, nonce=nonce, challenge=challenge)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    def test_challenge_rotated_after_success(self):
        challenge = "testchallenge"
        username = "alice"
        nonce = _find_nonce(challenge, username, difficulty=2)
        request = self._make_post("/register/", username, nonce=nonce, challenge=challenge)
        self.middleware(request)
        self.assertNotEqual(request.session["pow_challenge"], challenge)

    def test_get_request_not_enforced(self):
        request = self.factory.get("/register/")
        request.session = {}
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class TestSettings(TestCase):

    def test_defaults_returned_without_override(self):
        from django_pow.settings import DEFAULTS, get_settings
        with self.settings(DJANGO_POW={}):  # empty override → all defaults
            s = get_settings()
            for k, v in DEFAULTS.items():
                self.assertEqual(s[k], v)

    def test_user_overrides_applied(self):
        from django_pow.settings import get_settings
        with self.settings(DJANGO_POW={"DEFAULT_DIFFICULTY": 7}):
            s = get_settings()
            self.assertEqual(s["DEFAULT_DIFFICULTY"], 7)


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

@override_settings(
    DJANGO_POW=POW_SETTINGS_BASE,
    ROOT_URLCONF="django_pow.urls",  # or project urls
)
class TestViews(TestCase):

    def test_challenge_view_returns_json(self):
        from django.test import Client
        client = Client()
        session = client.session
        session.save()
        response = client.get("/challenge/")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("challenge", data)
        self.assertIn("difficulty", data)

    def test_challenge_view_path_difficulty(self):
        with self.settings(DJANGO_POW={**POW_SETTINGS_BASE, "PATH_DIFFICULTIES": {"/register/": 5}}):
            client = Client()
            response = client.get("/challenge/?path=/register/")
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.content)
            self.assertEqual(data["difficulty"], 5)

    def test_difficulty_view(self):
        client = Client()
        response = client.get("/difficulty/?path=/register/")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("difficulty", data)
