"""End-to-end check of the health contract against a stub Cloudflare API."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class StubCloudflare(BaseHTTPRequestHandler):
    mode = "ok"
    policy = {
        "id": "policy",
        "name": "JCM_WAN_TEST",
        "decision": "bypass",
        "include": [{"ip": {"ip": "198.51.100.1"}}],
        "require": [],
        "exclude": [],
    }

    def log_message(self, *_args):  # keep pytest output clean
        pass

    def _send(self, status, payload):
        body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ip":
            self._send(200, "203.0.113.77")
        elif self.path == "/accounts/acct/access/policies/policy":
            if self.mode == "forbidden":
                self._send(403, {"success": False, "errors": [{"message": "forbidden"}]})
            else:
                self._send(200, {"success": True, "result": self.policy})
        else:
            self._send(404, {"success": False})

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.policy.update(body)
        self._send(200, {"success": True, "result": self.policy})


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), StubCloudflare)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _run(args, env):
    return subprocess.run(
        [sys.executable, "-m", "cf_allowlist_updater.cli", *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src"), **env},
        capture_output=True,
        text=True,
        timeout=60,
    )


def _env(state_file, port, **overrides):
    env = {
        "CF_API_TOKEN": "token",
        "CF_ACCOUNT_ID": "acct",
        "CF_POLICY_ID": "policy",
        "CF_API_BASE_URL": f"http://127.0.0.1:{port}",
        "PUBLIC_IP_URL": f"http://127.0.0.1:{port}/ip",
        "PUBLIC_IP_URLS": f"http://127.0.0.1:{port}/ip",
        "IP_LOOKUP_ENABLED": "true",
        "ONCE": "true",
        "UPDATE_INTERVAL_MINUTES": "60",
        "HEALTH_STATE_FILE": state_file,
    }
    env.update(overrides)
    return env


def test_successful_cycle_marks_container_healthy(tmp_path):
    server = _serve()
    state_file = str(tmp_path / "state.json")
    try:
        port = server.server_address[1]
        result = _run([], _env(state_file, port))
        assert result.returncode == 0, result.stderr

        state = json.loads(open(state_file).read())
        assert state["last_success_ips"] == ["203.0.113.77"]
        assert state["consecutive_failures"] == 0
        assert state["last_error"] is None

        probe = _run(["--health"], _env(state_file, port))
        assert probe.returncode == 0, probe.stdout
        assert probe.stdout.startswith("ok:")
        assert "203.0.113.77" in probe.stdout
    finally:
        server.shutdown()


def test_failed_cycle_marks_container_unhealthy_with_the_api_error(tmp_path):
    server = _serve()
    StubCloudflare.mode = "forbidden"
    state_file = str(tmp_path / "state.json")
    try:
        port = server.server_address[1]
        result = _run([], _env(state_file, port, HEALTH_START_GRACE_SECONDS="0"))
        assert result.returncode == 1
        assert "ERROR" in result.stderr

        state = json.loads(open(state_file).read())
        assert state["last_success_at"] is None
        assert state["consecutive_failures"] == 1
        assert "forbidden" in state["last_error"].lower()

        probe = _run(["--health"], _env(state_file, port, HEALTH_START_GRACE_SECONDS="0"))
        assert probe.returncode == 1
        assert probe.stdout.startswith("unhealthy:")
        assert "forbidden" in probe.stdout.lower()
    finally:
        StubCloudflare.mode = "ok"
        server.shutdown()
