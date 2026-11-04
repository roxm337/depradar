"""Unit tests for depradarctl's pure parts. Run: python3 -m unittest discover -s deploy/tests"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "depradarctl"
loader = importlib.machinery.SourceFileLoader("depradarctl", str(TOOL))
spec = importlib.util.spec_from_loader("depradarctl", loader)
assert spec is not None
ctl = importlib.util.module_from_spec(spec)
loader.exec_module(ctl)


class EnvFileTest(unittest.TestCase):
    def test_round_trip_keeps_every_character_literal(self) -> None:
        values = {
            "PLAIN": "abc123",
            "SYMBOLS": 'p$ss"w#rd x\\y',
            "QUOTE": "it's $HOME \\ \"quoted\"",
            "EMPTY": "",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "depradar.env"
            path.write_text(ctl.render_env(values))
            self.assertEqual(ctl.read_env(path), values)

    def test_line_breaks_are_refused(self) -> None:
        with self.assertRaises(ctl.Abort):
            ctl.quote_env("a\nb")

    @unittest.skipUnless(
        shutil.which("docker")
        and subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0,
        "Docker Compose is not available",
    )
    def test_compose_reads_values_literally(self) -> None:
        values = {"A": 'p$ss"w#rd x', "B": "it's $HOME \\ \"q\""}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compose.yaml").write_text(
                "services:\n  t:\n    image: alpine\n    environment:\n      A: ${A}\n      B: ${B}\n"
            )
            (root / "e.env").write_text(ctl.render_env(values))
            output = subprocess.run(
                ["docker", "compose", "--env-file", "e.env", "config", "--format", "json"],
                cwd=root, capture_output=True, text=True, check=True,
            ).stdout
            environment = json.loads(output)["services"]["t"]["environment"]
            # `compose config` prints a literal $ as $$; the container receives a single $.
            self.assertEqual({k: v.replace("$$", "$") for k, v in environment.items()}, values)


def state(**overrides: object) -> dict:
    base = {"mode": "https", "domain": "depradar.example.com", "email": "ops@example.com"}
    base.update(overrides)
    return base


class RenderTest(unittest.TestCase):
    def test_https_site_gets_hsts_acme_email_and_routes(self) -> None:
        caddyfile = ctl.render_caddyfile(state())
        self.assertIn("email ops@example.com", caddyfile)
        self.assertIn("depradar.example.com {", caddyfile)
        self.assertIn("Strict-Transport-Security", caddyfile)
        self.assertNotIn("auto_https off", caddyfile)
        # The dashboard proxy must win over the broader /api/* route.
        self.assertLess(caddyfile.index("handle /api/backend/*"), caddyfile.index("@api path"))
        self.assertIn("max_size 11MB", caddyfile)
        self.assertEqual(ctl.public_url(state()), "https://depradar.example.com")
        self.assertIn('"443:443"', ctl.render_ports(state()))

    def test_internal_tls_uses_the_private_ca_without_hsts(self) -> None:
        caddyfile = ctl.render_caddyfile(state(mode="tls-internal", email=""))
        self.assertIn("tls internal", caddyfile)
        self.assertNotIn("Strict-Transport-Security", caddyfile)
        self.assertNotIn("email", caddyfile.split("}")[0])

    def test_internal_tls_can_share_the_host_with_another_site(self) -> None:
        current = state(mode="tls-internal", domain="72.60.39.60", email="", port=8443)
        self.assertIn("72.60.39.60:8443 {", ctl.render_caddyfile(current))
        # Clients send no SNI to an IP address, so Caddy must know which certificate to use.
        self.assertIn("default_sni 72.60.39.60", ctl.render_caddyfile(current))
        ports = ctl.render_ports(current)
        self.assertIn('"8443:8443"', ports)
        self.assertNotIn('"443:443"', ports)
        self.assertNotIn('"80:80"', ports)
        self.assertEqual(ctl.public_url(current), "https://72.60.39.60:8443")
        default = state(mode="tls-internal", domain="72.60.39.60", email="")
        self.assertEqual(ctl.public_url(default), "https://72.60.39.60")
        self.assertIn('"443:443"', ctl.render_ports(default))

    def test_proxy_mode_listens_on_loopback_only(self) -> None:
        current = {"mode": "proxy", "public_url": "https://deps.example.com/", "port": 8080}
        caddyfile = ctl.render_caddyfile(current)
        self.assertIn("auto_https off", caddyfile)
        self.assertIn(":80 {", caddyfile)
        self.assertIn('"127.0.0.1:8080:80"', ctl.render_ports(current))
        self.assertNotIn("443", ctl.render_ports(current))
        self.assertEqual(ctl.public_url(current), "https://deps.example.com")

    def test_http_mode_url_omits_the_default_port(self) -> None:
        self.assertEqual(ctl.public_url({"mode": "http", "host": "10.0.0.5", "port": 80}), "http://10.0.0.5")
        self.assertEqual(
            ctl.public_url({"mode": "http", "host": "10.0.0.5", "port": 8088}), "http://10.0.0.5:8088"
        )
        ports = ctl.render_ports({"mode": "http", "port": 8088, "bind": "10.0.0.5"})
        self.assertIn('"10.0.0.5:8088:80"', ports)


class ValidationTest(unittest.TestCase):
    def test_domains(self) -> None:
        self.assertIsNone(ctl.validate_domain("depradar.example.com"))
        self.assertIsNotNone(ctl.validate_domain("192.0.2.10"))
        self.assertIsNotNone(ctl.validate_domain("not a domain"))
        self.assertIsNotNone(ctl.validate_domain("localhost"))

    def test_hosts_ports_and_urls(self) -> None:
        self.assertIsNone(ctl.validate_host("192.0.2.10"))
        self.assertIsNone(ctl.validate_host("localhost"))
        self.assertIsNotNone(ctl.validate_port("0"))
        self.assertIsNone(ctl.validate_port("8080"))
        self.assertIsNone(ctl.validate_url("https://deps.example.com"))
        self.assertIsNotNone(ctl.validate_url("https://deps.example.com/dashboard"))
        self.assertIsNotNone(ctl.validate_url("deps.example.com"))

    def test_versions(self) -> None:
        self.assertGreaterEqual(ctl.version_tuple("v2.39.1"), ctl.MIN_COMPOSE)
        self.assertGreaterEqual(ctl.version_tuple("5.4.0"), ctl.MIN_COMPOSE)
        self.assertLess(ctl.version_tuple("2.20.3"), ctl.MIN_COMPOSE)


class PrivateWriteTest(unittest.TestCase):
    def test_files_are_created_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "secret.env"
            ctl.write_private(path, "KEY='value'\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            ctl.write_private(path, "KEY='other'\n")
            self.assertEqual(path.read_text(), "KEY='other'\n")


class CliTest(unittest.TestCase):
    def test_help_works_without_root_and_commands_need_root(self) -> None:
        help_text = subprocess.run(
            [sys.executable, str(TOOL), "--help"], capture_output=True, text=True, check=True
        ).stdout
        for command in ("install", "status", "upgrade", "backup", "restore", "doctor", "uninstall"):
            self.assertIn(command, help_text)
        if os.geteuid() != 0:
            result = subprocess.run(
                [sys.executable, str(TOOL), "status"], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("needs root", result.stdout)


if __name__ == "__main__":
    unittest.main()
