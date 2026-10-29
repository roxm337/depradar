"""Run OSV-Scanner on one manifest in a throwaway directory with a scrubbed environment."""

import json
import os
import signal
import subprocess
import tempfile
import threading
from pathlib import Path

from depradar.config import Settings
from depradar.domain.inventory import validate_inventory
from depradar.domain.scanning import ScannerReport, ScanResponse

scan_lock = threading.Lock()
OUTPUT_LIMIT = 32 * 1024 * 1024


class OsvError(Exception):
    """OSV-Scanner produced no usable report; the message is safe to return."""


class Busy(OsvError):
    pass


class TimedOut(OsvError):
    pass


class NoPackages(OsvError):
    pass


def scan(settings: Settings, content: bytes, filename: str) -> ScanResponse:
    if not scan_lock.acquire(blocking=False):
        raise Busy("Scanner is busy")
    try:
        with tempfile.TemporaryDirectory(prefix="depradar-scan-") as directory:
            root = Path(directory)
            inventory = root / filename
            inventory.write_bytes(content)
            # Empty config prevents inherited ignore rules from silently hiding findings.
            config = root / "osv-scanner.toml"
            config.write_text("")
            command = [
                settings.osv_binary,
                "scan",
                "source",
                "--format=json",
                "--all-packages",
                "--no-resolve",
                "--no-call-analysis=go",
                f"--config={config}",
                f"--lockfile={inventory}",
            ]
            env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": directory,
                "TMPDIR": directory,
                "XDG_CACHE_HOME": directory,
            }
            # Files avoid unbounded PIPE buffering; container tmpfs bounds disk use.
            with (root / "stdout").open("w+b") as out, (root / "stderr").open("w+b") as err:
                process = subprocess.Popen(
                    command, stdout=out, stderr=err, cwd=root, env=env, start_new_session=True
                )
                try:
                    code = process.wait(timeout=settings.scanner_timeout_seconds)
                except subprocess.TimeoutExpired as exc:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise TimedOut("Scanner timed out") from exc
                if code not in {0, 1}:
                    # Never return stderr: it can contain input data and external URLs.
                    raise OsvError(f"OSV-Scanner failed with exit code {code}")
                if out.tell() > OUTPUT_LIMIT:
                    raise OsvError("Scanner output exceeded limit")
                out.seek(0)
                report = ScannerReport.model_validate(json.load(out))
                err.seek(0)
                diagnostics = err.read(1024 * 1024).decode(errors="replace").lower()
            count = sum(len(source.packages) for source in report.results)
            if not count:
                raise NoPackages("Scanner did not identify any packages")
            notes = validate_inventory(filename, content)
            if "error" in diagnostics or "warn" in diagnostics:
                notes.append("Scanner diagnostics require review; findings will not auto-resolve")
            return ScanResponse(
                report=report, engine_version="osv-scanner 2.7.0", complete=not notes, notes=notes
            )
    except (OSError, ValueError) as exc:
        raise OsvError("Scanner unavailable or returned invalid output") from exc
    finally:
        scan_lock.release()
