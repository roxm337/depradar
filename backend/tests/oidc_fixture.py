"""A local OIDC issuer that signs CI identity tokens the way GitHub and GitLab do."""

import base64
import json
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from depradar.application.ports import IdentityRejected

GITHUB = "https://token.actions.githubusercontent.com"
GITLAB = "https://gitlab.example.com"
SHA = "0123456789abcdef0123456789abcdef01234567"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def number(value: int) -> str:
    return b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class Issuer:
    def __init__(self, url: str = GITHUB, bits: int = 2048, kid: str = "key-1") -> None:
        self.url = url
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.fetches: list[str] = []
        self.jwks_uri = url + "/.well-known/jwks"

    def jwk(self) -> dict[str, Any]:
        public = self.key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": number(public.n),
            "e": number(public.e),
        }

    def fetch(self, url: str) -> dict[str, Any]:
        self.fetches.append(url)
        if url == self.url + "/.well-known/openid-configuration":
            return {"issuer": self.url, "jwks_uri": self.jwks_uri}
        if url == self.jwks_uri:
            return {"keys": [self.jwk()]}
        raise IdentityRejected("Could not fetch the issuer's signing keys")

    def sign(
        self,
        claims: dict[str, Any],
        *,
        alg: str = "RS256",
        kid: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
    ) -> str:
        header = b64(json.dumps({"alg": alg, "kid": kid or self.kid, "typ": "JWT"}).encode())
        payload = b64(json.dumps({"iss": self.url, **claims}).encode())
        signature = (key or self.key).sign(
            f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{header}.{payload}.{b64(signature)}"


def github_claims(
    audience: str,
    *,
    event: str = "push",
    ref: str = "refs/heads/main",
    repository: str = "acme/web",
    repository_id: str = "4242",
    workflow: str = ".github/workflows/depradar.yml",
    head_ref: str = "",
    lifetime: int = 300,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "aud": audience,
        "sub": f"repo:{repository}:ref:{ref}",
        "repository": repository,
        "repository_id": repository_id,
        "repository_owner": repository.split("/")[0],
        "ref": ref,
        "ref_type": "tag" if ref.startswith("refs/tags/") else "branch",
        "sha": SHA,
        "workflow_ref": f"{repository}/{workflow}@{ref}",
        "event_name": event,
        "run_id": "777",
        "actor": "octocat",
        "head_ref": head_ref,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
    }


def gitlab_claims(
    audience: str,
    *,
    source: str = "push",
    ref: str = "main",
    protected: bool = True,
    project: str = "acme/api",
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "aud": audience,
        "project_path": project,
        "project_id": 99,
        "ref": ref,
        "ref_type": "branch",
        "ref_protected": "true" if protected else "false",
        "sha": SHA,
        "ci_config_ref_uri": f"gitlab.example.com/{project}//.gitlab-ci.yml@refs/heads/{ref}",
        "pipeline_source": source,
        "pipeline_id": 555,
        "job_id": 556,
        "user_login": "dev",
        "iat": now,
        "exp": now + 300,
    }
