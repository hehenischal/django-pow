"""
Core PoW logic: challenge generation and hash verification.
"""

import hashlib
import os

from . import settings as pow_settings


# ---------------------------------------------------------------------------
# Challenge helpers
# ---------------------------------------------------------------------------

def generate_challenge(length: int | None = None) -> str:
    """
    Return a cryptographically random hex challenge string.

    Args:
        length: Number of random bytes.  Defaults to ``CHALLENGE_LENGTH``.

    Returns:
        A lowercase hex string of length ``length * 2``.
    """
    length = length or pow_settings.get("CHALLENGE_LENGTH")
    return os.urandom(length).hex()


def get_challenge_for_request(request) -> str:
    """
    Return the current session challenge, creating one if absent.

    The challenge is stored in the session under ``CHALLENGE_SESSION_KEY``.
    """
    key = pow_settings.get("CHALLENGE_SESSION_KEY")
    if key not in request.session:
        request.session[key] = generate_challenge()
    return request.session[key]


def rotate_challenge(request) -> str:
    """
    Invalidate the current challenge and issue a fresh one.

    Call this after a successful PoW to prevent replay attacks.
    """
    key = pow_settings.get("CHALLENGE_SESSION_KEY")
    request.session[key] = generate_challenge()
    return request.session[key]


# ---------------------------------------------------------------------------
# Difficulty helpers
# ---------------------------------------------------------------------------

def get_difficulty(path: str | None = None) -> int:
    """
    Return the PoW difficulty for the given URL path.

    Checks ``PATH_DIFFICULTIES`` for a matching prefix/exact match first,
    then falls back to ``DEFAULT_DIFFICULTY``.

    Args:
        path: URL path string, e.g. ``"/register/"``.

    Returns:
        Integer difficulty (number of leading zeros required).
    """
    overrides: dict = pow_settings.get("PATH_DIFFICULTIES")
    if path and overrides:
        # Exact match first
        if path in overrides:
            return int(overrides[path])
        # Prefix match (longest wins)
        matches = {p: d for p, d in overrides.items() if path.startswith(p)}
        if matches:
            best = max(matches, key=len)
            return int(matches[best])
    return int(pow_settings.get("DEFAULT_DIFFICULTY"))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _get_hasher(algorithm: str):
    """Return a hashlib constructor for the requested algorithm."""
    algo = algorithm.lower()
    supported = {"sha256": hashlib.sha256, "sha512": hashlib.sha512, "md5": hashlib.md5}
    if algo not in supported:
        raise ValueError(
            f"Unsupported hash algorithm '{algorithm}'. "
            f"Choose from: {', '.join(supported)}"
        )
    return supported[algo]


def compute_hash(challenge: str, username: str, nonce: str | int, algorithm: str | None = None) -> str:
    """
    Compute the PoW hash for the given parameters.

    The preimage is: ``{challenge}{username}{nonce}``  (UTF-8 encoded)

    Args:
        challenge: The session challenge string.
        username:  The identity field value from the request.
        nonce:     The nonce found by the client.
        algorithm: Hash algorithm name; defaults to ``HASH_ALGORITHM`` setting.

    Returns:
        Lowercase hex digest string.
    """
    algorithm = algorithm or pow_settings.get("HASH_ALGORITHM")
    hasher = _get_hasher(algorithm)
    content = f"{challenge}{username}{nonce}".encode("utf-8")
    return hasher(content).hexdigest()


def verify_proof_of_work(
    challenge: str,
    username: str,
    nonce: str | int,
    difficulty: int | None = None,
    algorithm: str | None = None,
) -> tuple[bool, str]:
    """
    Verify that a nonce satisfies the Proof of Work requirement.

    Args:
        challenge:  Session challenge string.
        username:   Identity value (from POST data / JSON body).
        nonce:      Nonce submitted by the client.
        difficulty: Required leading zeros; defaults to ``DEFAULT_DIFFICULTY``.
        algorithm:  Hash algorithm; defaults to ``HASH_ALGORITHM`` setting.

    Returns:
        ``(True, hash_hex)`` on success, ``(False, hash_hex)`` on failure.
    """
    if difficulty is None:
        difficulty = pow_settings.get("DEFAULT_DIFFICULTY")

    result_hash = compute_hash(challenge, username, nonce, algorithm)
    prefix = "0" * int(difficulty)
    return result_hash.startswith(prefix), result_hash
