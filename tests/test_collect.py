import json
from datetime import datetime, timezone

import httpx
import pytest
from omini_sdk import Change, Config, PluginError
from omini_sdk.plugin import Plugin

import main  # noqa: F401  (registers the functions on the SDK's plugin)
import omini_adguard.collect as collect_module
from omini_adguard.collect import apply, backup, collect
from omini_adguard.collect import test as check


def change(kind, value):
    return Change(device="192.168.1.53", kind=kind, value=value)


def names(dev):
    return [(r.name, r.ip) for r in dev.dns_records or []]


def test_collect_reads_the_server(adguard, cfg):
    [dev] = collect(cfg)
    assert dev.key == "192.168.1.53" and dev.host == "192.168.1.53"
    assert (dev.name, dev.role, dev.vendor, dev.model) == (
        "AdGuard Home",
        "server",
        "AdGuard",
        "AdGuard Home",
    )
    assert dev.os_version == "0.107.57"
    # Loopback and link-local addresses are not the server's addresses on the network.
    assert dev.ips == ["192.168.1.53"]
    # Only exact names answered with an IPv4 address: no wildcard, CNAME or IPv6.
    assert names(dev) == [("nas.home.arpa", "192.168.1.20"), ("printer.home.arpa", "192.168.1.30")]
    assert [(s.name, s.running, s.enabled) for s in dev.services] == [
        ("DNS", True, True),
        ("DHCP", True, True),
    ]


def test_collect_reads_dhcp_when_on(adguard, cfg):
    [dev] = collect(cfg)
    assert [
        (lease.ip, lease.mac, lease.hostname, lease.expires_at) for lease in dev.dhcp_leases
    ] == [
        (
            "192.168.1.101",
            "aa:bb:cc:dd:ee:01",
            "laptop",
            datetime(2026, 10, 12, 18, tzinfo=timezone.utc),
        ),
        ("192.168.1.102", "aa:bb:cc:dd:ee:02", None, None),
    ]
    assert [(r.mac, r.ip, r.name) for r in dev.dhcp_reservations] == [
        ("aa:bb:cc:dd:ee:20", "192.168.1.20", "nas")
    ]
    [pool] = dev.dhcp_pools
    assert (pool.network, pool.total, pool.used) == ("192.168.1.0/24", 100, 2)
    assert dev.dns_domain is None


def lookups(dev):
    return [(x.client, x.domain, x.answers) for x in dev.dns_lookups or []]


def test_collect_reads_the_query_log(adguard, cfg):
    [dev] = collect(cfg)
    assert ("GET", "/control/querylog") in adguard.calls
    # One per client and name, newest first, with the union of A/AAAA answers;
    # a blocked answer (0.0.0.0) has no address, nor does one without answer.
    assert lookups(dev) == [
        ("192.168.1.42", "example.com", ["93.184.216.34", "2606:2800:220:1::248"]),
        ("192.168.1.50", "ads.example.net", None),
        ("192.168.1.50", "cached.example.org", None),
    ]


def test_collect_caps_the_lookups(adguard, cfg, monkeypatch):
    monkeypatch.setattr(collect_module, "MAX_LOOKUPS", 2)
    [dev] = collect(cfg)
    assert [d for _, d, _ in lookups(dev)] == ["example.com", "ads.example.net"]


def test_collect_asks_for_a_thousand_entries(adguard, cfg):
    seen = []

    def handler(request):
        if request.url.path == "/control/querylog":
            seen.append(request.url.params.get("limit"))
        return adguard.handler(request)

    adguard.hook = handler
    collect(cfg)
    assert seen == ["1000"]


@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(200, json={"oldest": "", "data": []}),  # query log off
        httpx.Response(500, text="boom"),
        httpx.Response(404, text="404 page not found"),
    ],
)
def test_collect_without_the_query_log(adguard, cfg, answer):
    def handler(request):
        if request.url.path == "/control/querylog":
            return answer
        return adguard.handler(request)

    adguard.hook = handler
    [dev] = collect(cfg)
    assert dev.dns_lookups is None
    assert names(dev)  # the rest is read as usual


def test_collect_with_an_older_omini(adguard, cfg, monkeypatch):
    monkeypatch.setattr(collect_module, "DnsLookup", None)
    [dev] = collect(cfg)
    assert dev.dns_lookups is None
    assert ("GET", "/control/querylog") not in adguard.calls


def test_collect_without_dhcp(adguard, cfg):
    adguard.dhcp = {"enabled": False, "leases": [], "static_leases": []}
    [dev] = collect(cfg)
    assert dev.dhcp_leases is None and dev.dhcp_reservations is None and dev.dhcp_pools is None
    assert [(s.name, s.running) for s in dev.services] == [("DNS", True), ("DHCP", False)]


def test_collect_with_a_build_without_dhcp(adguard, cfg):
    def handler(request):
        if request.url.path == "/control/dhcp/status":
            return httpx.Response(404, text="404 page not found")
        return adguard.handler(request)

    adguard.hook = handler
    [dev] = collect(cfg)
    assert [s.name for s in dev.services] == ["DNS"]


def test_disabled_rewrites_are_not_answered(adguard, cfg):
    adguard.rewrites.append({"domain": "old.home.arpa", "answer": "192.168.1.9", "enabled": False})
    [dev] = collect(cfg)
    assert ("old.home.arpa", "192.168.1.9") not in names(dev)


def test_wrong_password(adguard, cfg):
    cfg["password"] = "nope"
    with pytest.raises(PluginError, match="rejected the username or password"):
        collect(cfg)


def test_test_returns_the_version(adguard, cfg):
    assert check(cfg) == "Connected to AdGuard Home 0.107.57, 2 local names"


def test_address_without_scheme(adguard):
    [dev] = collect(
        Config({"url": "adguard.lan:3000", "username": "omini", "password": "s3cret-pass"})
    )
    assert dev.key == "adguard.lan"


# -- dns.set / dns.delete --


def test_dns_set_adds_a_name(adguard, cfg):
    [dev] = apply(cfg, change("dns.set", {"name": "NAS2.home.arpa.", "ip": "192.168.1.21"}))
    assert ("nas2.home.arpa", "192.168.1.21") in names(dev)
    assert adguard.writes() == [("POST", "/control/rewrite/add")]


def test_dns_set_changes_the_address_of_the_same_name(adguard, cfg):
    [dev] = apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.25"}))
    assert ("nas.home.arpa", "192.168.1.25") in names(dev)
    assert ("nas.home.arpa", "192.168.1.20") not in names(dev)
    assert [r for r in adguard.rewrites if r["domain"] == "nas.home.arpa"] == [
        {"domain": "nas.home.arpa", "answer": "192.168.1.25"}
    ]
    assert adguard.writes() == [("PUT", "/control/rewrite/update")]


def test_dns_set_on_versions_without_update(adguard, cfg):
    adguard.has_update = False
    apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.25"}))
    assert [r for r in adguard.rewrites if r["domain"] == "nas.home.arpa"] == [
        {"domain": "nas.home.arpa", "answer": "192.168.1.25"}
    ]
    assert adguard.writes() == [
        ("PUT", "/control/rewrite/update"),
        ("POST", "/control/rewrite/delete"),
        ("POST", "/control/rewrite/add"),
    ]


def test_dns_set_puts_the_old_one_back_when_the_add_is_refused(adguard, cfg):
    adguard.has_update = False
    adguard.refuse.add("/control/rewrite/add")
    added = []

    def handler(request):
        # Refuse only the new answer, accept the restore.
        if request.url.path == "/control/rewrite/add" and b"192.168.1.20" in request.content:
            adguard.refuse.discard("/control/rewrite/add")
            added.append(True)
        return adguard.handler(request)

    adguard.hook = handler
    with pytest.raises(PluginError, match="refused POST /control/rewrite/add"):
        apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.25"}))
    assert added == [True]
    assert {"domain": "nas.home.arpa", "answer": "192.168.1.20"} in adguard.rewrites


def test_dns_set_merges_duplicates(adguard, cfg):
    adguard.rewrites.append({"domain": "nas.home.arpa", "answer": "192.168.1.99"})
    apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.20"}))
    assert [r for r in adguard.rewrites if r["domain"] == "nas.home.arpa"] == [
        {"domain": "nas.home.arpa", "answer": "192.168.1.20"}
    ]


def test_dns_set_already_there_changes_nothing(adguard, cfg):
    apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.20"}))
    assert adguard.writes() == []


def test_dns_set_refuses_bad_values(adguard, cfg):
    with pytest.raises(PluginError, match="IPv4"):
        apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "fd00::1"}))
    with pytest.raises(PluginError, match="name is required"):
        apply(cfg, change("dns.set", {"name": "*.home.arpa", "ip": "192.168.1.2"}))
    with pytest.raises(PluginError, match="does not support"):
        apply(cfg, change("pause.set", {"mac": "aa:bb:cc:dd:ee:01"}))
    assert adguard.writes() == []


def test_dns_set_refused_by_the_server(adguard, cfg):
    adguard.refuse.add("/control/rewrite/add")
    with pytest.raises(PluginError, match="invalid rewrite"):
        apply(cfg, change("dns.set", {"name": "new.home.arpa", "ip": "192.168.1.5"}))


def test_dns_set_not_kept_fails_the_verification(adguard, cfg):
    def handler(request):
        resp = adguard.handler(request)
        if request.url.path == "/control/rewrite/add":
            adguard.rewrites.pop()  # accepted, then lost
        return resp

    adguard.hook = handler
    with pytest.raises(PluginError, match=r"did not keep new\.home\.arpa"):
        apply(cfg, change("dns.set", {"name": "new.home.arpa", "ip": "192.168.1.5"}))


def test_dns_delete(adguard, cfg):
    [dev] = apply(cfg, change("dns.delete", {"name": "printer.home.arpa"}))
    assert names(dev) == [("nas.home.arpa", "192.168.1.20")]
    # A name that is not there: nothing to do.
    adguard.calls.clear()
    apply(cfg, change("dns.delete", {"name": "printer.home.arpa"}))
    assert adguard.writes() == []


# -- backup --


def test_backup_is_sorted_json_without_live_state(adguard, cfg):
    [b] = backup(cfg)
    assert (b.device, b.format) == ("192.168.1.53", "json")
    data = json.loads(b.content)
    assert set(data) == {"status", "rewrites", "dns", "filtering", "clients", "dhcp", "access"}
    assert "running" not in data["status"] and "start_time" not in data["status"]
    assert data["status"]["version"] == "v0.107.57"
    assert "leases" not in data["dhcp"] and data["dhcp"]["static_leases"][0]["ip"] == "192.168.1.20"
    assert set(data["filtering"]["filters"][0]) == {"id", "enabled", "url", "name"}
    assert [c["name"] for c in data["clients"]] == ["Kids tablet"]
    assert b.content == json.dumps(data, sort_keys=True, indent=2) + "\n"


def test_backup_is_deterministic(adguard, cfg):
    first = backup(cfg)[0].content
    # Live state moves: leases, counters, the start time, the filter lists' updates.
    adguard.status["start_time"] += 3600
    adguard.dhcp["leases"].append({"mac": "aa:bb:cc:dd:ee:03", "ip": "192.168.1.103"})
    adguard.filtering["filters"][0]["rules_count"] += 10
    adguard.filtering["filters"][0]["last_updated"] = "2026-10-13T08:00:00Z"
    adguard.clients["auto_clients"].append({"name": "phone", "ip": "192.168.1.104"})
    assert backup(cfg)[0].content == first
    # A configuration change shows.
    adguard.rewrites.append({"domain": "new.home.arpa", "answer": "192.168.1.5"})
    assert backup(cfg)[0].content != first


def test_plugin_runtime(adguard, cfg):
    from omini_sdk import plugin

    assert isinstance(plugin, Plugin)
    req = {"protocol": 1, "action": "backup", "config": dict(cfg)}
    out, code = plugin.handle(json.dumps(req))
    assert code == 0 and out["backups"][0]["device"] == "192.168.1.53"
