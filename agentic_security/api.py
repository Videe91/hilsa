from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from .control_plane import ControlPlane
from .models import DecisionInput

cp = ControlPlane()


def _read_json(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    data = handler.rfile.read(length) if length > 0 else b"{}"
    return json.loads(data.decode("utf-8"))


def _send_json(handler: BaseHTTPRequestHandler, code: int, payload: Any) -> None:
    raw = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


class APIServer(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/authorize":
            payload = _read_json(self)
            request = DecisionInput(
                agent_id=payload["agent_id"],
                action=payload["action"],
                resource=payload["resource"],
                context=payload.get("context", {}),
            )
            result = cp.authorize(request)
            _send_json(self, 200, result)
            return

        if path.startswith("/kill-switch/"):
            agent_id = path.split("/", 2)[2]
            revoked = cp.kill_switch(agent_id)
            _send_json(self, 200, {"revoked": revoked})
            return

        if path == "/tokens/validate":
            payload = _read_json(self)
            valid = cp.tokens.validate(payload["token"], payload["agent_id"])
            _send_json(self, 200, {"valid": valid})
            return

        _send_json(self, 404, {"error": "not_found"})

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/audit/events":
            events = [event.__dict__ for event in cp.audit.list_events()]
            _send_json(self, 200, events)
            return
        _send_json(self, 404, {"error": "not_found"})


def create_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), APIServer)


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = create_server(host, port)
    server.serve_forever()
