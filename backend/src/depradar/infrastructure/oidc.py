"""Verify CI OIDC identity tokens (RS256 JWTs) against their issuers' published signing keys.

Signing keys are fetched only for issuers the owner trusts, never for an issuer named by the
token itself, so a forged token cannot make the server contact an arbitrary host.
"""

import base64
import binascii
import json
import math
import re
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from depradar.application.ports import IdentityRejected

MAX_TOKEN_BYTES = 16 * 1024
MAX_DOCUMENT_BYTES = 512 * 1024
LEEWAY_SECONDS = 60
KEYS_TTL_SECONDS = 600
REFRESH_INTERVAL_SECONDS = 60
# While an issuer is unreachable its last keys stay usable this long, so exchanges keep working.
MAX_STALE_SECONDS = 86400
MIN_KEY_BITS = 2048
BASE64URL = re.compile(r"[A-Za-z0-9_-]*")

# (url) -> parsed JSON document
Fetch = Callable[[str], dict[str, Any]]


def fetch_json(url: str) -> dict[str, Any]:
    body = bytearray()
    try:
        with httpx.Client(timeout=10, follow_redirects=False) as client:
            with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
                response.raise_for_status()
                # Stream with a cap so an oversized document is never held in memory.
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_DOCUMENT_BYTES:
                        raise IdentityRejected("The issuer's key document is too large")
        value = json.loads(body)
    except (httpx.HTTPError, ValueError, RecursionError) as exc:
        raise IdentityRejected("Could not fetch the issuer's signing keys") from exc
    if not isinstance(value, dict):
        raise IdentityRejected("The issuer returned an unexpected key document")
    return value


def _segment(value: str) -> bytes:
    # Strict base64url: lenient decoders silently drop foreign characters.
    if not BASE64URL.fullmatch(value):
        raise IdentityRejected("The identity token is malformed")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise IdentityRejected("The identity token is malformed") from exc


def _reject_constant(value: str) -> None:
    raise ValueError(f"{value} is not valid JSON")


def _json_segment(value: str) -> dict[str, Any]:
    try:
        # Python's parser accepts NaN and Infinity, which would defeat the lifetime checks.
        decoded = json.loads(_segment(value), parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:  # deeply nested input exhausts the stack
        raise IdentityRejected("The identity token is malformed") from exc
    if not isinstance(decoded, dict):
        raise IdentityRejected("The identity token is malformed")
    return decoded


def _integer(value: Any) -> int:
    if not isinstance(value, str):
        raise ValueError("not a base64url string")
    return int.from_bytes(_segment(value), "big")


def rsa_keys(document: dict[str, Any]) -> dict[str, rsa.RSAPublicKey]:
    keys: dict[str, rsa.RSAPublicKey] = {}
    for entry in document.get("keys", []) if isinstance(document.get("keys"), list) else []:
        if not isinstance(entry, dict) or entry.get("kty") != "RSA":
            continue
        if entry.get("use", "sig") != "sig" or not isinstance(entry.get("kid"), str):
            continue
        try:
            key = rsa.RSAPublicNumbers(_integer(entry["e"]), _integer(entry["n"])).public_key()
        except (KeyError, ValueError, IdentityRejected):
            continue
        if key.key_size >= MIN_KEY_BITS:
            keys[entry["kid"]] = key
    return keys


class JwksVerifier:
    """Thread-safe RS256 verifier with a per-issuer signing-key cache."""

    def __init__(self, fetch: Fetch = fetch_json, clock: Callable[[], float] = time.time):
        self.fetch = fetch
        self.clock = clock
        self.lock = threading.Lock()  # guards the two dictionaries below, never a fetch
        # issuer -> (keys fetched at, last fetch attempt, keys by key ID)
        self.cache: dict[str, tuple[float, float, dict[str, rsa.RSAPublicKey]]] = {}
        self.fetching: dict[str, threading.Lock] = {}

    def keys(self, issuer: str, kid: str) -> rsa.RSAPublicKey:
        with self.lock:
            fetching = self.fetching.setdefault(issuer, threading.Lock())
        # One fetch per issuer at a time; other issuers never wait on a slow one.
        with fetching:
            now = self.clock()
            with self.lock:
                fetched_at, attempted_at, keys = self.cache.get(issuer, (0.0, 0.0, {}))
            due = now - attempted_at > REFRESH_INTERVAL_SECONDS
            # Refresh expired keys, and unknown key IDs (issuers rotate keys), once a minute.
            if due and (now - fetched_at > KEYS_TTL_SECONDS or kid not in keys):
                try:
                    keys = rsa_keys(self.fetch(self._jwks_uri(issuer)))
                    fetched_at = now
                except IdentityRejected:
                    if not keys or now - fetched_at > MAX_STALE_SECONDS:
                        raise
                with self.lock:
                    self.cache[issuer] = (fetched_at, now, keys)
        key = keys.get(kid)
        if key is None:
            raise IdentityRejected("The identity token was signed with an unknown key")
        return key

    def _jwks_uri(self, issuer: str) -> str:
        document = self.fetch(issuer.rstrip("/") + "/.well-known/openid-configuration")
        uri = document.get("jwks_uri")
        parts = urlsplit(uri) if isinstance(uri, str) else None
        if parts is None or parts.scheme != "https" or parts.hostname != urlsplit(issuer).hostname:
            raise IdentityRejected("The issuer publishes its signing keys at an unexpected URL")
        return str(uri)

    def __call__(self, token: str, issuers: set[str], audience: str) -> dict[str, Any]:
        if len(token) > MAX_TOKEN_BYTES or token.count(".") != 2:
            raise IdentityRejected("The identity token is malformed")
        header_part, payload_part, signature_part = token.split(".")
        header = _json_segment(header_part)
        claims = _json_segment(payload_part)
        # Pin the algorithm: "none", HMAC, and others can never verify here.
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise IdentityRejected("The identity token must be signed with RS256")
        issuer = claims.get("iss")
        if not isinstance(issuer, str) or issuer not in issuers:
            raise IdentityRejected("The identity token comes from an untrusted issuer")
        key = self.keys(issuer, header["kid"])
        try:
            key.verify(
                _segment(signature_part),
                f"{header_part}.{payload_part}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, UnicodeEncodeError) as exc:
            raise IdentityRejected("The identity token signature is invalid") from exc
        self._check_claims(claims, audience)
        return claims

    def _check_claims(self, claims: dict[str, Any], audience: str) -> None:
        now = self.clock()

        def moment(name: str) -> float | None:
            value = claims.get(name)
            if value is None:
                return None
            valid = isinstance(value, int | float) and not isinstance(value, bool)
            if not valid or not math.isfinite(value):
                raise IdentityRejected(f"The identity token has an invalid {name} claim")
            return float(value)

        expires = moment("exp")
        if expires is None or expires <= now - LEEWAY_SECONDS:
            raise IdentityRejected("The identity token has expired")
        for name in ("nbf", "iat"):
            value = moment(name)
            if value is not None and value > now + LEEWAY_SECONDS:
                raise IdentityRejected("The identity token is not valid yet")
        accepted = claims.get("aud")
        audiences = accepted if isinstance(accepted, list) else [accepted]
        if audience not in audiences:
            raise IdentityRejected(
                f"The identity token audience must be {audience}; request it with that audience"
            )
