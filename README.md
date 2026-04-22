# Django-POW

**Proof of Work protection for Django views.**  
Stop bots, slow down credential-stuffing attacks, and rate-limit expensive endpoints — all at the *client* level with zero server-side cost.

---

## How it works

1. The server issues a random **challenge** stored in the user's session.
2. The client JavaScript mines a **nonce** such that  
   `SHA-256(challenge + username + nonce)` starts with N leading zeros.
3. The nonce is sent in the `X-PoW-Nonce` HTTP header.
4. Django middleware / decorator verifies the hash before the view runs.
5. The challenge is **rotated** on every successful submission to prevent replay attacks.

---

## Installation

```bash
pip install django-pow
```

Add to `INSTALLED_APPS` and `MIDDLEWARE`:

```python
# settings.py

INSTALLED_APPS = [
    ...
    "django_pow",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",  # must be before
    "django_pow.middleware.ProofOfWorkMiddleware",
    ...
]
```

Include the built-in URLs (needed for the challenge endpoint):

```python
# urls.py
from django.urls import path, include

urlpatterns = [
    path("pow/", include("django_pow.urls")),
    ...
]
```

---

## Configuration

All settings live under a single `DJANGO_POW` dict in `settings.py`.  
Every key is optional — sensible defaults are provided.

```python
DJANGO_POW = {
    # Number of leading zeros required in the PoW hash
    "DEFAULT_DIFFICULTY": 4,

    # Byte length of the random session challenge (hex length = 2×)
    "CHALLENGE_LENGTH": 16,

    # Session key used to store/retrieve the challenge
    "CHALLENGE_SESSION_KEY": "pow_challenge",

    # Django META key for the header carrying the nonce
    "NONCE_HEADER": "HTTP_X_POW_NONCE",   # corresponds to X-PoW-Nonce

    # POST/JSON field used as the identity component in the hash preimage
    "USERNAME_FIELD": "username",

    # Per-path difficulty overrides (exact or prefix match, longest wins)
    "PATH_DIFFICULTIES": {
        "/register/": 5,
        "/api/auth/": 3,
    },

    # Paths the middleware will enforce PoW on
    "PROTECTED_PATHS": ["/register/", "/login/"],

    # HTTP methods to enforce (only POST by default)
    "PROTECTED_METHODS": ["POST"],

    # HTTP status returned on failure
    "ERROR_STATUS_CODE": 403,

    # Skip PoW for already-authenticated users
    "SKIP_FOR_AUTHENTICATED": False,

    # Hash algorithm: "sha256" | "sha512" | "md5"
    "HASH_ALGORITHM": "sha256",
}
```

---

## Usage

### Option 1 — Middleware (protect paths globally)

Set `PROTECTED_PATHS` in settings; the middleware handles everything:

```python
DJANGO_POW = {
    "PROTECTED_PATHS": ["/register/", "/login/"],
    "PATH_DIFFICULTIES": {"/register/": 5, "/login/": 3},
}
```

### Option 2 — `@require_pow` decorator (per-view)

```python
from django_pow.decorators import require_pow

@require_pow(difficulty=5)
def register(request):
    ...
```

### Option 3 — `ProofOfWorkMixin` (class-based views)

```python
from django_pow.decorators import ProofOfWorkMixin

class RegisterView(ProofOfWorkMixin, CreateView):
    pow_difficulty = 5
    template_name = "register.html"
    ...
```

---

## Frontend integration

### Auto-init (easiest)

Add `data-pow` to your form and load the scripts:

```html
{% load static %}
<script src="{% static 'django_pow/django-pow.js' %}"></script>

<form action="/register/" method="post" data-pow data-pow-status="#pow-status">
  {% csrf_token %}
  <input name="username" ...>
  <input name="password" ...>
  <p id="pow-status"></p>
  <button type="submit">Register</button>
</form>
```

That's it. The library will:
- fetch the challenge from `/pow/challenge/?path=/register/`
- spawn a Web Worker to mine the nonce
- attach `X-PoW-Nonce` to the request
- update `#pow-status` with progress

### Template tag (embed challenge in page)

```html
{% load pow_tags %}
{% pow_challenge_data path="/register/" %}
{# Renders <script>window.POW_CONFIG = {...};</script> #}
```

### Manual JavaScript API

```js
const pow = new DjangoPOW({ workerUrl: "/static/django_pow/pow_worker.js" });

// Mine manually
const { nonce, hash, attempts } = await pow.mine({
  challenge: "abc123",
  difficulty: 4,
  username: "alice",
  algorithm: "sha256",
});

// Then include in your fetch:
fetch("/register/", {
  method: "POST",
  headers: { "X-PoW-Nonce": nonce },
  body: formData,
});
```

### Events

```js
window.addEventListener("djpow:progress", (e) => console.log("attempts:", e.detail));
window.addEventListener("djpow:submitted", (e) => console.log("response:", e.detail));
```

---

## Challenge / nonce API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/pow/challenge/` | Return current session challenge + difficulty |
| `GET`  | `/pow/challenge/?path=/register/` | Challenge with per-path difficulty |
| `POST` | `/pow/challenge/` | Force-rotate the challenge |
| `GET`  | `/pow/difficulty/?path=/register/` | Query difficulty for a path |

---

## Hash preimage

The hash input is always:

```
SHA-256( f"{challenge}{username}{nonce}".encode("utf-8") )
```

This matches both the Python middleware and the JavaScript worker exactly.

---

## Running tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Security notes

- **Difficulty tuning**: Difficulty 4 requires ~65 000 hashes on average.  
  Difficulty 5 → ~1 million. Start at 4 and tune for your hardware.
- **Replay protection**: The challenge rotates after every successful POST.
- **Session requirement**: Sessions must be enabled (`SessionMiddleware` must come before `ProofOfWorkMiddleware`).
- **Not a captcha replacement**: PoW adds friction cost for bots; it does not prove humanity. Combine with rate limiting for best results.

---

## License

MIT
