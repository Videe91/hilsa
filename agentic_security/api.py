from __future__ import annotations

import json
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import urlparse

from .control_plane import ControlPlane
from .models import DecisionInput

cp = ControlPlane()
API_TOKEN = os.environ.get("AGENTIC_SECURITY_API_TOKEN", "dev-token")


def _read_json(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    data = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid_json:{exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid_json:payload_must_be_object")
    return payload


def _send_json(handler: BaseHTTPRequestHandler, code: int, payload: Any, request_id: str) -> None:
    if isinstance(payload, dict):
        payload = {"request_id": request_id, **payload}
    raw = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("X-Request-Id", request_id)
    handler.end_headers()
    handler.wfile.write(raw)


def _require_auth(handler: BaseHTTPRequestHandler) -> bool:
    auth = handler.headers.get("Authorization", "")
    return auth == f"Bearer {API_TOKEN}"


def _validate_authorize_payload(payload: Dict[str, Any]) -> None:
    required = ["agent_id", "action", "resource"]
    for key in required:
        if key not in payload or not isinstance(payload[key], str) or not payload[key].strip():
            raise ValueError(f"invalid_payload:{key}")
    context = payload.get("context", {})
    if not isinstance(context, dict):
        raise ValueError("invalid_payload:context")
    for k, v in context.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValueError("invalid_payload:context_kv")


class APIServer(BaseHTTPRequestHandler):
    def _dispatch(self) -> None:
        request_id = str(uuid.uuid4())
        start = time.time()
        path = urlparse(self.path).path

        if not _require_auth(self):
            _send_json(self, 401, {"error": "unauthorized"}, request_id)
            return

        try:
            if self.command == "POST" and path == "/authorize":
                payload = _read_json(self)
                _validate_authorize_payload(payload)
                request = DecisionInput(
                    agent_id=payload["agent_id"],
                    action=payload["action"],
                    resource=payload["resource"],
                    context=payload.get("context", {}),
                )
                result = cp.authorize(request)
                result["latency_ms"] = int((time.time() - start) * 1000)
                _send_json(self, 200, result, request_id)
                return

            if self.command == "POST" and path.startswith("/kill-switch/"):
                agent_id = path.split("/", 2)[2]
                if not agent_id:
                    _send_json(self, 400, {"error": "invalid_payload:agent_id"}, request_id)
                    return
                revoked = cp.kill_switch(agent_id)
                _send_json(self, 200, {"revoked": revoked, "latency_ms": int((time.time() - start) * 1000)}, request_id)
                return

            if self.command == "POST" and path == "/tokens/validate":
                payload = _read_json(self)
                token = payload.get("token")
                agent_id = payload.get("agent_id")
                if not isinstance(token, str) or not isinstance(agent_id, str):
                    _send_json(self, 400, {"error": "invalid_payload:token_or_agent_id"}, request_id)
                    return
                valid = cp.tokens.validate(token, agent_id)
                _send_json(self, 200, {"valid": valid, "latency_ms": int((time.time() - start) * 1000)}, request_id)
                return

            if self.command == "GET" and path == "/audit/events":
                events = [event.__dict__ for event in cp.audit.list_events()]
                _send_json(self, 200, {"events": events, "latency_ms": int((time.time() - start) * 1000)}, request_id)
                return

            _send_json(self, 404, {"error": "not_found"}, request_id)
        except ValueError as exc:
            _send_json(self, 400, {"error": str(exc)}, request_id)

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()


def create_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), APIServer)


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = create_server(host, port)
    server.serve_forever()
