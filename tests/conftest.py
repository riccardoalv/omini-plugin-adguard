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
        # Newest first, as /control/querylog answers.
        self.querylog = {
            "oldest": "2026-10-12T17:00:00Z",
            "data": [
                {
                    "client": "192.168.1.42",
                    "question": {"class": "IN", "name": "Example.com.", "type": "A"},
                    "answer": [
                        {"type": "CNAME", "value": "edge.example.net.", "ttl": 300},
                        {"type": "A", "value": "93.184.216.34", "ttl": 300},
                    ],
                    "reason": "NotFilteredNotFound",
                    "status": "NOERROR",
                    "time": "2026-10-12T17:59:00Z",
                },
                {
                    "client": "192.168.1.42",
                    "question": {"class": "IN", "name": "example.com", "type": "AAAA"},
                    "answer": [{"type": "AAAA", "value": "2606:2800:220:1::248", "ttl": 300}],
                    "reason": "NotFilteredNotFound",
                    "time": "2026-10-12T17:58:00Z",
                },
                {
                    "client": "192.168.1.42",
                    "question": {"class": "IN", "name": "example.com", "type": "A"},
                    "answer": [{"type": "A", "value": "93.184.216.34", "ttl": 120}],
                    "cached": True,
                    "time": "2026-10-12T17:57:00Z",
                },
                {
                    "client": "192.168.1.50",
                    "question": {"class": "IN", "name": "ads.example.net", "type": "A"},
                    "answer": [{"type": "A", "value": "0.0.0.0", "ttl": 10}],
                    "reason": "FilteredBlackList",
                    "time": "2026-10-12T17:56:00Z",
                },
                {
                    "client": "192.168.1.50",
                    "question": {"class": "IN", "name": "cached.example.org.", "type": "A"},
                    "answer": None,
                    "time": "2026-10-12T17:55:00Z",
                },
                {"client": "", "question": {"name": "nobody.example"}, "answer": []},
                {"client": "192.168.1.51", "question": {"name": ""}, "answer": []},
            ],
        }
        # GET /control/dhcp/interfaces: NetInterfaces, a map by name (Go sorts
        # the keys); loopback and interfaces without broadcast are left out.
        self.interfaces = {
            "docker0": {
                "name": "docker0",
                "hardware_address": "02:42:5e:6f:70:81",
                "flags": "up|broadcast|multicast",
                "ipv4_addresses": ["172.17.0.1"],
                "ipv6_addresses": [],
            },
            "eth0": {
                "name": "eth0",
                "hardware_address": "dc:a6:32:11:22:33",
                "flags": "up|broadcast|multicast|running",
                "gateway_ip": "192.168.1.1",
                "ipv4_addresses": ["192.168.1.53"],
                "ipv6_addresses": ["2001:db8:1::53", "fe80::dea6:32ff:fe11:2233"],
            },
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
                "/control/querylog": lambda: self.querylog,
                "/control/dhcp/interfaces": lambda: self.interfaces,
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
            i = self.find(body)
            if i is None:
                return httpx.Response(400, text="rewrite not found")
            del self.rewrites[i]
            return httpx.Response(200, text="OK")
        if method == "PUT" and path == "/control/rewrite/update" and self.has_update:
            i = self.find(body["target"])
            if i is None:
                return httpx.Response(400, text="rewrite not found")
            update = body["update"]
            self.rewrites[i] = {"domain": update["domain"], "answer": update["answer"]} | (
                {"enabled": update["enabled"]} if "enabled" in update else {}
            )
            return httpx.Response(200, text="OK")
        return httpx.Response(405 if path.startswith("/control/") else 404, text="not allowed")

    def find(self, target):
        """The index of the rewrite with that domain and answer."""
        for i, r in enumerate(self.rewrites):
            if (r["domain"], r["answer"]) == (target["domain"], target["answer"]):
                return i
        return None

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
