"""Client for AdGuard Home's HTTP API (``/control/...``), on the SDK's HTTP
client: timeouts, retries, and errors that say what went wrong.

Every request carries HTTP basic authentication with the web interface's
username and password. Reads are ``GET`` and answer JSON; changes are
``POST`` (or ``PUT``) with a JSON body and answer ``OK`` or nothing, and a
refused change answers 400 with the reason as plain text.
"""

from __future__ import annotations

from typing import Any

import httpx
from omini_sdk.http import Client as HttpClient
from omini_sdk.http import NotFound, Unauthorized

__all__ = ["Client", "NotFound"]

REJECTED = "AdGuard Home rejected the username or password (use the account of its web interface)"


class Client(HttpClient):
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 15,
        transport: httpx.BaseTransport | None = None,
    ):
        super().__init__(
            url,
            name="AdGuard Home",
            scheme="http",
            verify_tls=verify_tls,
            timeout=timeout,
            auth=httpx.BasicAuth(username, password),
            user_agent="omini-plugin-adguard",
            unauthorized=REJECTED,
            transport=transport,
        )

    def check(self, r: httpx.Response, method: str, path: str) -> None:
        """AdGuard Home answers 403 for a wrong password too, and 405 for an
        endpoint this version lacks."""
        where = {"status": r.status_code, "method": method, "resource": path}
        if r.status_code == 403:
            raise Unauthorized(REJECTED, **where)
        if r.status_code == 405:
            raise NotFound(f"AdGuard Home has no {path}", **where)
        super().check(r, method, path)

    def get(self, path: str) -> Any:  # type: ignore[override]
        return self.request("GET", path)

    def post(self, path: str, body: Any) -> Any:  # type: ignore[override]
        return self.request("POST", path, json=body)

    def put(self, path: str, body: Any) -> Any:  # type: ignore[override]
        return self.request("PUT", path, json=body)

    def request(self, method: str, path: str, **kw: Any) -> Any:
        """A change answers "OK" (not JSON): None for it."""
        method = method.upper()
        if method == "GET":
            return super().request(method, path, **kw)
        r = self.send(method, path, **kw)
        self.check(r, method, path)
        return None
