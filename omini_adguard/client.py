"""Minimal client for AdGuard Home's HTTP API (``/control/...``).

Every request carries HTTP basic authentication with the web interface's
username and password. Reads are ``GET`` and answer JSON; changes are
``POST`` (or ``PUT``) with a JSON body and answer ``OK`` or nothing, and a
refused change answers 400 with the reason as plain text.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from omini_sdk import PluginError


class NotFound(Exception):
    """The endpoint does not exist on this version (404 or 405)."""


class Client:
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 10,
        transport: httpx.BaseTransport | None = None,
    ):
        url = url.strip().rstrip("/")
        if not url.startswith(("https://", "http://")):
            url = "http://" + url
        self.base = url
        self.http = httpx.Client(
            base_url=url,
            verify=verify_tls,
            timeout=timeout,
            auth=httpx.BasicAuth(username, password),
            headers={"Accept": "application/json", "User-Agent": "omini-plugin-adguard"},
            transport=transport,
        )

    def close(self) -> None:
        self.http.close()

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, body: Any) -> Any:
        return self.request("POST", path, body)

    def put(self, path: str, body: Any) -> Any:
        return self.request("PUT", path, body)

    def request(self, method: str, path: str, body: Any = None) -> Any:
        try:
            r = self.http.request(method, path, json=body)
        except httpx.ConnectError as e:
            raise PluginError(f"cannot connect to {self.base}: {e}") from e
        except httpx.TimeoutException as e:
            raise PluginError(f"{self.base} did not answer in time") from e
        except httpx.HTTPError as e:
            raise PluginError(f"request to {self.base} failed: {e}") from e
        if r.status_code in (401, 403):
            raise PluginError(
                "AdGuard Home rejected the username or password (use the account of its web "
                "interface)"
            )
        if r.status_code in (404, 405):
            raise NotFound(path)
        if r.status_code >= 400:
            reason = r.text.strip() or f"HTTP {r.status_code}"
            if method != "GET":
                raise PluginError(f"AdGuard Home refused {method} {path}: {reason}")
            raise PluginError(f"AdGuard Home answered {r.status_code} for {path}")
        if method != "GET":
            return None
        try:
            return r.json()
        except json.JSONDecodeError as e:
            raise PluginError(
                f"{self.base} did not answer with JSON: is it AdGuard Home's web interface?"
            ) from e
