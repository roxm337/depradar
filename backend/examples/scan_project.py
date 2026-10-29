"""Interactive API walkthrough; never prints or writes credentials/session cookies."""

import getpass
import time
from pathlib import Path

import httpx


def main() -> None:
    with httpx.Client(base_url="http://localhost:8000", timeout=20, trust_env=False) as client:
        status = client.get("/api/auth/status")
        status.raise_for_status()
        password = getpass.getpass("Owner password (12–128 characters): ")
        if not status.json()["initialized"]:
            token = getpass.getpass("Bootstrap token from .env: ")
            response = client.post(
                "/api/auth/bootstrap",
                json={"password": password},
                headers={"X-Bootstrap-Token": token},
            )
        else:
            response = client.post("/api/auth/login", json={"password": password})
        response.raise_for_status()
        headers = {"X-CSRF-Token": response.json()["csrf_token"]}
        response = client.post(
            "/api/projects", json={"name": f"Example {int(time.time())}"}, headers=headers
        )
        response.raise_for_status()
        project_id = response.json()["id"]
        response = client.post(
            f"/api/projects/{project_id}/inventories",
            params={"filename": "package-lock.json"},
            headers=headers,
            content=Path(__file__).with_name("package-lock.json").read_bytes(),
        )
        response.raise_for_status()
        scan_id = response.json()["scan"]["id"]
        print(f"Project {project_id}; queued scan {scan_id}")
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            response = client.get(f"/api/scans/{scan_id}")
            response.raise_for_status()
            scan = response.json()
            if scan["status"] in {"succeeded", "partial", "failed", "superseded"}:
                print(f"Scan: {scan['status']}; packages: {scan['package_count']}")
                if scan["error"]:
                    print(scan["error"])
                findings = client.get(f"/api/projects/{project_id}/findings")
                findings.raise_for_status()
                for finding in findings.json():
                    print(
                        f"{finding['package_name']}@{finding['package_version']}: "
                        f"{', '.join(finding['advisory_ids'])} ({finding['severity']})"
                    )
                return
            time.sleep(2)
        raise SystemExit("Scan is still pending; inspect GET /api/jobs and worker logs")


if __name__ == "__main__":
    main()
