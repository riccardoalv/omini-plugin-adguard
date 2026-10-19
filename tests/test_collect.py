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

MAC = "dc:a6:32:11:22:33"


def change(kind, value):
    return Change(device=MAC, kind=kind, value=value)


def names(dev):
    return [(r.name, r.ip) for r in dev.dns_records or []]


def test_collect_reads_the_server(adguard, cfg):
    [dev] = collect(cfg)
    # Keyed by the MAC of the interface holding its address, like Pi-hole.
    assert dev.key == MAC and dev.host == "192.168.1.53"
    assert [m.root for m in dev.macs] == [MAC]
    assert (dev.name, dev.role, dev.vendor, dev.model) == (
        "AdGuard Home",
        "server",
        "AdGuard",
        "AdGuard Home",
    )
    assert dev.os_version == "0.107.57"
    # Loopback and link-local addresses are not the server's addresses on the network.
    assert dev.ips == ["192.168.1.53"]
    # Exact names answered with an address, IPv4 or IPv6: no wildcard or CNAME.
    assert names(dev) == [
        ("nas.home.arpa", "192.168.1.20"),
        ("printer.home.arpa", "192.168.1.30"),
        ("v6.home.arpa", "fd00::20"),
    ]
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
    # one without answer has no address. Blocked queries reached nothing.
    assert lookups(dev) == [
        ("192.168.1.42", "example.com", ["93.184.216.34", "2606:2800:220:1::248"]),
        ("192.168.1.50", "cached.example.org", None),
    ]


@pytest.mark.parametrize(
    "reason",
    ["FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental", "FilteredBlockedService"],
)
def test_collect_leaves_blocked_queries_out(adguard, cfg, reason):
    adguard.querylog["data"] = [
        {
            "client": "192.168.1.60",
            "question": {"name": "tracker.example", "type": "A"},
            "answer": [{"type": "A", "value": "203.0.113.9", "ttl": 10}],
            "reason": reason,
        }
    ]
    [dev] = collect(cfg)
    assert dev.dns_lookups is None


@pytest.mark.parametrize("client", ["0.0.0.0", "::", "not-an-address"])
def test_collect_leaves_hidden_clients_out(adguard, cfg, client):
    adguard.querylog["data"] = [
        {"client": client, "question": {"name": "example.com", "type": "A"}, "answer": []}
    ]
    [dev] = collect(cfg)
    assert dev.dns_lookups is None


def test_collect_caps_the_lookups(adguard, cfg, monkeypatch):
    monkeypatch.setattr(collect_module, "MAX_LOOKUPS", 1)
    [dev] = collect(cfg)
    assert [d for _, d, _ in lookups(dev)] == ["example.com"]


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
    assert check(cfg) == "Connected to AdGuard Home 0.107.57, 3 local names"


def test_address_without_scheme(adguard):
    [dev] = collect(
        Config({"url": "adguard.lan:3000", "username": "omini", "password": "s3cret-pass"})
    )
    # A name, not an address: the first interface with an address.
    assert dev.key == "02:42:5e:6f:70:81"


def test_key_by_an_ipv6_address(adguard):
    [dev] = collect(
        Config(
            {"url": "http://[2001:db8:1::53]:3000", "username": "omini", "password": "s3cret-pass"}
        )
    )
    assert dev.key == MAC and dev.host == "2001:db8:1::53"


def test_key_skips_loopback_and_interfaces_without_a_mac(adguard, cfg):
    adguard.interfaces = {
        "lo": {"name": "lo", "hardware_address": "", "flags": "up|loopback"},
        "tun0": {"name": "tun0", "hardware_address": "", "ipv4_addresses": ["10.8.0.1"]},
        "wlan0": {"name": "wlan0", "hardware_address": "DC:A6:32:11:22:44", "flags": "broadcast"},
    }
    [dev] = collect(cfg)
    assert dev.key == "dc:a6:32:11:22:44"


@pytest.mark.parametrize("status", [403, 404, 500])
def test_without_the_interfaces_the_address_is_the_key(adguard, cfg, status):
    def handler(request):
        if request.url.path == "/control/dhcp/interfaces":
            return httpx.Response(status, text="no")
        return adguard.handler(request)

    adguard.hook = handler
    [dev] = collect(cfg)
    assert dev.key == "192.168.1.53" and dev.macs is None
    assert names(dev)  # the rest is read as usual
    assert backup(cfg)[0].device == "192.168.1.53"


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


def test_dns_set_puts_the_old_one_back_when_the_add_answers_404(adguard, cfg):
    adguard.has_update = False

    def handler(request):
        # The add of the new answer is not found; the restore goes through.
        if request.url.path == "/control/rewrite/add" and b"192.168.1.25" in request.content:
            return httpx.Response(404, text="404 page not found")
        return adguard.handler(request)

    adguard.hook = handler
    with pytest.raises(PluginError, match="has no /control/rewrite/add"):
        apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.25"}))
    assert {"domain": "nas.home.arpa", "answer": "192.168.1.20"} in adguard.rewrites


def test_dns_set_merges_duplicates(adguard, cfg):
    adguard.rewrites.append({"domain": "nas.home.arpa", "answer": "192.168.1.99"})
    apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.20"}))
    assert [r for r in adguard.rewrites if r["domain"] == "nas.home.arpa"] == [
        {"domain": "nas.home.arpa", "answer": "192.168.1.20"}
    ]


OTHERS = [
    {"domain": "nas.home.arpa", "answer": "fd00::20"},  # AAAA
    {"domain": "nas.home.arpa", "answer": "storage.home.arpa"},  # CNAME
]


def test_dns_set_leaves_ipv6_and_cname_rewrites_alone(adguard, cfg):
    adguard.rewrites[:0] = OTHERS  # before the A one, so they come first
    [dev] = apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.25"}))
    assert ("nas.home.arpa", "192.168.1.25") in names(dev)
    assert [r for r in adguard.rewrites if r["domain"] == "nas.home.arpa"] == [
        *OTHERS,
        {"domain": "nas.home.arpa", "answer": "192.168.1.25"},
    ]


def test_dns_set_adds_beside_ipv6_and_cname_rewrites(adguard, cfg):
    adguard.rewrites[:0] = [{**r, "domain": "new.home.arpa"} for r in OTHERS]
    apply(cfg, change("dns.set", {"name": "new.home.arpa", "ip": "192.168.1.5"}))
    assert [r["answer"] for r in adguard.rewrites if r["domain"] == "new.home.arpa"] == [
        "fd00::20",
        "storage.home.arpa",
        "192.168.1.5",
    ]
    assert adguard.writes() == [("POST", "/control/rewrite/add")]


def test_dns_delete_leaves_ipv6_and_cname_rewrites_alone(adguard, cfg):
    adguard.rewrites[:0] = OTHERS
    [dev] = apply(cfg, change("dns.delete", {"name": "nas.home.arpa"}))
    assert ("nas.home.arpa", "192.168.1.20") not in names(dev)
    assert ("nas.home.arpa", "fd00::20") in names(dev)  # still read, never deleted
    assert [r for r in adguard.rewrites if r["domain"] == "nas.home.arpa"] == OTHERS


def test_dns_set_switches_a_disabled_rewrite_on(adguard, cfg):
    adguard.rewrites.append({"domain": "old.home.arpa", "answer": "192.168.1.9", "enabled": False})
    [dev] = apply(cfg, change("dns.set", {"name": "old.home.arpa", "ip": "192.168.1.9"}))
    assert ("old.home.arpa", "192.168.1.9") in names(dev)
    assert adguard.rewrites[-1] == {
        "domain": "old.home.arpa",
        "answer": "192.168.1.9",
        "enabled": True,
    }


def test_dns_set_changes_a_disabled_rewrite_and_switches_it_on(adguard, cfg):
    adguard.rewrites.append({"domain": "old.home.arpa", "answer": "192.168.1.9", "enabled": False})
    [dev] = apply(cfg, change("dns.set", {"name": "old.home.arpa", "ip": "192.168.1.8"}))
    assert ("old.home.arpa", "192.168.1.8") in names(dev)
    assert adguard.rewrites[-1]["enabled"] is True


def test_dns_set_a_rewrite_left_disabled_fails_the_verification(adguard, cfg):
    adguard.rewrites.append({"domain": "old.home.arpa", "answer": "192.168.1.9", "enabled": False})

    def handler(request):
        resp = adguard.handler(request)
        if request.url.path == "/control/rewrite/update":
            adguard.rewrites[-1]["enabled"] = False  # accepted, but still off
        return resp

    adguard.hook = handler
    with pytest.raises(PluginError, match=r"did not keep old\.home\.arpa"):
        apply(cfg, change("dns.set", {"name": "old.home.arpa", "ip": "192.168.1.8"}))


def test_dns_delete_leaves_disabled_rewrites_alone(adguard, cfg):
    off = {"domain": "nas.home.arpa", "answer": "192.168.1.9", "enabled": False}
    adguard.rewrites.append(off)
    apply(cfg, change("dns.delete", {"name": "nas.home.arpa"}))
    assert [r for r in adguard.rewrites if r["domain"] == "nas.home.arpa"] == [off]


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


@pytest.mark.parametrize("name", ["nas\thome.arpa", "nas\nhome.arpa", "nas,home.arpa"])
def test_dns_set_refuses_names_with_whitespace_or_commas(adguard, cfg, name):
    with pytest.raises(PluginError, match="name is required"):
        apply(cfg, change("dns.set", {"name": name, "ip": "192.168.1.2"}))
    assert adguard.writes() == []


def test_collect_leaves_all_zero_macs_out(adguard, cfg):
    adguard.dhcp["leases"].append({"mac": "00:00:00:00:00:00", "ip": "192.168.1.150"})
    adguard.dhcp["static_leases"].append({"mac": "00-00-00-00-00-00", "ip": "192.168.1.151"})
    [dev] = collect(cfg)
    assert "192.168.1.150" not in [lease.ip for lease in dev.dhcp_leases]
    assert "192.168.1.151" not in [r.ip for r in dev.dhcp_reservations]


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
    assert names(dev) == [("nas.home.arpa", "192.168.1.20"), ("v6.home.arpa", "fd00::20")]
    # A name that is not there: nothing to do.
    adguard.calls.clear()
    apply(cfg, change("dns.delete", {"name": "printer.home.arpa"}))
    assert adguard.writes() == []


# -- backup --


def test_backup_is_sorted_json_without_live_state(adguard, cfg):
    [b] = backup(cfg)
    assert (b.device, b.format) == (MAC, "json")
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
    assert code == 0 and out["backups"][0]["device"] == MAC


def test_ipv6_rewrites_are_read_as_records(adguard, cfg):
    adguard.rewrites += [
        {"domain": "nas.home.arpa", "answer": "2001:DB8:0:0::20"},  # AAAA beside the A
        {"domain": "blocked.home.arpa", "answer": "::"},  # a block, not an address
        {"domain": "off.home.arpa", "answer": "fd00::9", "enabled": False},
    ]
    [dev] = collect(cfg)
    assert names(dev) == [
        ("nas.home.arpa", "192.168.1.20"),  # IPv4 first
        ("nas.home.arpa", "2001:db8::20"),  # in its short form
        ("printer.home.arpa", "192.168.1.30"),
        ("v6.home.arpa", "fd00::20"),
    ]


def test_dns_set_on_a_name_with_only_an_ipv6_answer_adds_the_ipv4_one(adguard, cfg):
    [dev] = apply(cfg, change("dns.set", {"name": "v6.home.arpa", "ip": "192.168.1.60"}))
    assert [r["answer"] for r in adguard.rewrites if r["domain"] == "v6.home.arpa"] == [
        "fd00::20",
        "192.168.1.60",
    ]
    assert ("v6.home.arpa", "fd00::20") in names(dev)


def test_dhcpv6_leases_are_read(adguard, cfg):
    adguard.dhcp["v6"]["range_start"] = "2001:db8:1::100"
    # AdGuard Home lists DHCPv6 leases with the IPv4 ones.
    adguard.dhcp["leases"] += [
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:DB8:1::101", "hostname": "laptop", "expires": ""},
        {"mac": "aa:bb:cc:dd:ee:03", "ip": "fe80::3", "hostname": "", "expires": ""},
    ]
    # A v6 section with its own leases is read too, each address once.
    adguard.dhcp["v6"]["leases"] = [
        {"mac": "aa:bb:cc:dd:ee:04", "ip": "fd00::104", "hostname": "tv", "expires": ""},
        {"mac": "aa:bb:cc:dd:ee:01", "ip": "2001:db8:1::101", "hostname": "laptop", "expires": ""},
    ]
    [dev] = collect(cfg)
    assert [(lease.ip, lease.mac, lease.hostname) for lease in dev.dhcp_leases] == [
        ("192.168.1.101", "aa:bb:cc:dd:ee:01", "laptop"),
        ("192.168.1.102", "aa:bb:cc:dd:ee:02", None),
        ("2001:db8:1::101", "aa:bb:cc:dd:ee:01", "laptop"),
        ("fd00::104", "aa:bb:cc:dd:ee:04", "tv"),
    ]
    # The pool is the IPv4 range: the DHCPv6 leases are not counted in it.
    assert dev.dhcp_pools[0].used == 2


def test_backup_leaves_dhcpv6_leases_out(adguard, cfg):
    adguard.dhcp["v6"]["leases"] = [{"mac": "aa:bb:cc:dd:ee:04", "ip": "fd00::104"}]
    [b] = backup(cfg)
    assert "fd00::104" not in b.content


# -- the SDK toolkit: retries, the wait and the undo --


def test_a_change_not_kept_is_put_back(adguard, cfg, pauses):
    def handler(request):
        resp = adguard.handler(request)
        if request.method == "PUT" and request.url.path == "/control/rewrite/update":
            body = json.loads(request.content)
            if body["update"]["answer"] == "192.168.1.25":
                adguard.rewrites[adguard.find(body["update"])]["answer"] = "192.168.1.99"
        return resp

    adguard.hook = handler
    with pytest.raises(
        PluginError,
        match=r"did not keep nas\.home\.arpa → 192\.168\.1\.25: "
        r"it answers nas\.home\.arpa with 192\.168\.1\.99 \(undone\)$",
    ):
        apply(cfg, change("dns.set", {"name": "nas.home.arpa", "ip": "192.168.1.25"}))
    # Read again every 2 s for 30 s, then put back as it was.
    assert pauses == [collect_module.POLL_S] * 15
    assert {"domain": "nas.home.arpa", "answer": "192.168.1.20"} in adguard.rewrites
    assert not any(r["answer"] == "192.168.1.99" for r in adguard.rewrites)


def test_a_delete_not_done_is_said(adguard, cfg):
    def handler(request):
        if request.url.path == "/control/rewrite/delete":
            return httpx.Response(200, text="OK")  # accepted, not done
        return adguard.handler(request)

    adguard.hook = handler
    with pytest.raises(
        PluginError,
        match=r"did not delete nas\.home\.arpa: it answers nas\.home\.arpa with 192\.168\.1\.20",
    ):
        apply(cfg, change("dns.delete", {"name": "nas.home.arpa"}))


def test_a_busy_server_is_asked_again(adguard, cfg, pauses):
    busy = {"left": 1}

    def handler(request):
        if busy["left"]:
            busy["left"] -= 1
            return httpx.Response(503, text="busy")
        return adguard.handler(request)

    adguard.hook = handler
    [dev] = collect(cfg)
    assert dev.key == MAC and pauses == [1.0]


def test_the_timeout_comes_from_the_form(adguard, cfg, monkeypatch):
    seen = {}
    real = collect_module.Client

    def spy(*a, **kw):
        seen.update(kw)
        return real(*a, **kw)

    monkeypatch.setattr(collect_module, "Client", spy)
    collect(cfg)
    assert seen == {"verify_tls": False, "timeout": 15.0}
    cfg["timeout_s"] = 40
    collect(cfg)
    assert seen["timeout"] == 40.0


def test_manifest_groups_the_advanced_fields():
    from pathlib import Path

    manifest = (Path(__file__).parent.parent / "plugin.yaml").read_text()
    fields = manifest.split("\nfields:", 1)[1].split("\n  - key: ")[1:]
    groups = {f.split("\n", 1)[0]: "group: Advanced" in f for f in fields}
    assert groups == {
        "url": False,
        "username": False,
        "password": False,
        "verify_tls": True,
        "timeout_s": True,
    }
