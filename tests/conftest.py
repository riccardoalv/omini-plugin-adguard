import base64
import copy
from functools import partial

import httpx
import pytest
from omini_sdk import Config

import omini_adguard.collect as collect_module
from omini_adguard.client import Client

USER, PASSWORD = "omini", "s3cret-pass"


class FakeAdGuard:
    """AdGuard Home v0.107 answering its HTTP API (openapi.yaml of the project),
    with state: rewrites, persistent clients, filters, access lists and DHCP."""

    def __init__(self):
        self.calls = []
        self.hook = None  # a test's own handler in front of this one
        self.version = "v0.107.57"
        self.has_update = True  # PUT /control/rewrite/update (v0.107.55+)
        self.refuse = set()  # paths whose POST/PUT answer 400
        self.status = {
            "dns_addresses": ["127.0.0.1", "192.168.1.53", "fe80::1"],
            "dns_port": 53,
            "http_port": 3000,
            "protection_enabled": True,
            "protection_disabled_duration": 0,
            "dhcp_available": True,
            "running": True,
            "language": "en",
            "start_time": 1791370000000,
        }
        self.rewrites = [
            {"domain": "nas.home.arpa", "answer": "192.168.1.20"},
            {"domain": "printer.home.arpa", "answer": "192.168.1.30"},
            {"domain": "*.lab.home.arpa", "answer": "192.168.1.40"},
            {"domain": "media.home.arpa", "answer": "nas.home.arpa"},
            {"domain": "v6.home.arpa", "answer": "fd00::20"},
        ]
        self.dhcp = {
            "enabled": True,
            "interface_name": "eth0",
            "v4": {
                "gateway_ip": "192.168.1.1",
                "subnet_mask": "255.255.255.0",
                "range_start": "192.168.1.100",
                "range_end": "192.168.1.199",
                "lease_duration": 86400,
            },
            "v6": {"range_start": "", "lease_duration": 86400},
            "leases": [
                {
                    "mac": "AA:BB:CC:DD:EE:01",
                    "ip": "192.168.1.101",
                    "hostname": "laptop",
                    "expires": "2026-10-12T18:00:00Z",
                },
                {"mac": "aa:bb:cc:dd:ee:02", "ip": "192.168.1.102", "hostname": "", "expires": ""},
            ],
            "static_leases": [
                {"mac": "aa:bb:cc:dd:ee:20", "ip": "192.168.1.20", "hostname": "nas"},
            ],
        }
        self.dns_info = {
            "upstream_dns": ["https://dns10.quad9.net/dns-query"],
            "bootstrap_dns": ["9.9.9.10"],
            "ratelimit": 20,
            "cache_size": 4194304,
        }
        self.filtering = {
            "enabled": True,
            "interval": 24,
            "filters": [
                {
                    "id": 1,
                    "enabled": True,
                    "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
                    "name": "AdGuard DNS filter",
                    "rules_count": 61000,
                    "last_updated": "2026-10-12T08:00:00Z",
                }
            ],
            "whitelist_filters": [],
            "user_rules": ["@@||example.org^"],
        }
        self.clients = {
            "clients": [
                {"name": "Kids tablet", "ids": ["192.168.1.50"], "use_global_settings": True}
            ],
            "auto_clients": [{"name": "laptop", "ip": "192.168.1.101", "source": "dhcp"}],
            "supported_tags": ["device_pc"],
        }
        self.access = {
            "allowed_clients": [],
            "disallowed_clients": [],
            "blocked_hosts": ["id.server"],
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append((method, path))
        want = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if request.headers.get("authorization") != want:
            return httpx.Response(401, text="Unauthorized")
        if method == "GET":
            routes = {
                "/control/status": lambda: {**self.status, "version": self.version},
                "/control/rewrite/list": lambda: self.rewrites,
                "/control/dhcp/status": lambda: self.dhcp,
                "/control/dns_info": lambda: self.dns_info,
                "/control/filtering/status": lambda: self.filtering,
                "/control/clients": lambda: self.clients,
                "/control/access/list": lambda: self.access,
            }
            if path not in routes:
                return httpx.Response(404, text="404 page not found")
            return httpx.Response(200, json=copy.deepcopy(routes[path]()))
        if path in self.refuse:
            return httpx.Response(400, text="control/rewrite: invalid rewrite")
        body = httpx.Response(200, content=request.content).json()
        if method == "POST" and path == "/control/rewrite/add":
            row = {"domain": body["domain"], "answer": body["answer"]}
            if row in self.rewrites:
                return httpx.Response(400, text="rewrite already exists")
            self.rewrites.append(row)
            return httpx.Response(200, text="OK")
        if method == "POST" and path == "/control/rewrite/delete":
            row = {"domain": body["domain"], "answer": body["answer"]}
            if row not in self.rewrites:
                return httpx.Response(400, text="rewrite not found")
            self.rewrites.remove(row)
            return httpx.Response(200, text="OK")
        if method == "PUT" and path == "/control/rewrite/update" and self.has_update:
            target = {"domain": body["target"]["domain"], "answer": body["target"]["answer"]}
            if target not in self.rewrites:
                return httpx.Response(400, text="rewrite not found")
            i = self.rewrites.index(target)
            self.rewrites[i] = {
                "domain": body["update"]["domain"],
                "answer": body["update"]["answer"],
            }
            return httpx.Response(200, text="OK")
        return httpx.Response(405 if path.startswith("/control/") else 404, text="not allowed")

    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]


@pytest.fixture
def adguard(monkeypatch):
    fake = FakeAdGuard()
    monkeypatch.setattr(
        collect_module,
        "Client",
        partial(Client, transport=httpx.MockTransport(lambda r: (fake.hook or fake.handler)(r))),
    )
    return fake


@pytest.fixture
def cfg():
    return Config({"url": "http://192.168.1.53:3000", "username": USER, "password": PASSWORD})
