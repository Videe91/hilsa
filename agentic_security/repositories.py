from __future__ import annotations

import sqlite3
import threading
from typing import Dict, List, Optional

from .audit import AuditEvent
from .tokens import CapabilityToken


class SQLiteRepository:
    def __init__(self, db_path: str = "agentic_security.db") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tokens (
                    token TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )


class TokenRepository(SQLiteRepository):
    def save(self, token: CapabilityToken) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO tokens (token,agent_id,action,resource,expires_at,revoked) VALUES (?,?,?,?,?,?)",
                (token.token, token.agent_id, token.action, token.resource, token.expires_at, int(token.revoked)),
            )

    def get(self, token: str) -> Optional[CapabilityToken]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT token,agent_id,action,resource,expires_at,revoked FROM tokens WHERE token=?", (token,)
            ).fetchone()
        if not row:
            return None
        return CapabilityToken(
            token=row[0],
            agent_id=row[1],
            action=row[2],
            resource=row[3],
            expires_at=row[4],
            revoked=bool(row[5]),
        )

    def revoke(self, token: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("UPDATE tokens SET revoked=1 WHERE token=?", (token,))
            return cur.rowcount > 0

    def revoke_agent(self, agent_id: str) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute("UPDATE tokens SET revoked=1 WHERE agent_id=? AND revoked=0", (agent_id,))
            return cur.rowcount


class AuditRepository(SQLiteRepository):
    def save(self, event: AuditEvent) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_events (ts,agent_id,action,resource,decision,reasons,metadata) VALUES (?,?,?,?,?,?,?)",
                (
                    event.ts,
                    event.agent_id,
                    event.action,
                    event.resource,
                    event.decision,
                    "|".join(event.reasons),
                    "|".join(f"{k}={v}" for k, v in event.metadata.items()),
                ),
            )

    def list_events(self) -> List[AuditEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts,agent_id,action,resource,decision,reasons,metadata FROM audit_events ORDER BY id ASC"
            ).fetchall()
        out: List[AuditEvent] = []
        for row in rows:
            metadata: Dict[str, str] = {}
            if row[6]:
                for pair in row[6].split("|"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        metadata[k] = v
            out.append(
                AuditEvent(
                    ts=row[0],
                    agent_id=row[1],
                    action=row[2],
                    resource=row[3],
                    decision=row[4],
                    reasons=row[5].split("|") if row[5] else [],
                    metadata=metadata,
                )
            )
        return out
