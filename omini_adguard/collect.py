"""AdGuard Home: the server itself, its local DNS names (rewrites), its DHCP
server's leases and fixed addresses, and the dns.set / dns.delete changes."""

from __future__ import annotations

import contextlib
import ipaddress
import json
from collections.abc import Callable
from datetime import datetime
from typing import Any, TypeVar
from urllib.parse import urlsplit

from omini_sdk import (
    Change,
    Config,
    ConfigBackup,
    Device,
    DhcpLease,
    DhcpPool,
    DhcpReservation,
    DnsRecord,
    PluginError,
    Service,
    log,
)

try:  # DNS lookups: Omini 1.6 and later
    from omini_sdk import DnsLookup
except ImportError:
    DnsLookup = None  # type: ignore[assignment,misc]

from omini_adguard.client import Client, NotFound

T = TypeVar("T")

# Fields of /control/status that are live state, not configuration.
LIVE_STATUS = {
    "running",
    "start_time",
    "protection_disabled_duration",
    "protection_disabled_until",
    "dhcp_available",
    "dns_addresses",
}
# Fields of a filter list that change with every update of the list.
LIVE_FILTER = {"rules_count", "last_updated"}
# Entries read from the query log, and distinct (client, name) lookups kept.
QUERYLOG_LIMIT = 1000
MAX_LOOKUPS = 500


def client_from(cfg: Config) -> Client:
    url = cfg.str("url")
    if not url:
        raise PluginError("the address is required")
    return Client(
        url,
        cfg.str("username"),
        cfg.str("password"),
        verify_tls=cfg.bool("verify_tls"),
    )


def host_of(cfg: Config) -> str:
    """The host part of the address, as the user typed it (the device's key)."""
    url = cfg.str("url").strip()
    if "://" not in url:
        url = "http://" + url
    return (urlsplit(url).hostname or url).lower()


def optional(fn: Callable[[], T], default: T) -> T:
    """An endpoint some versions or builds lack (404): its default instead."""
    try:
        return fn()
    except NotFound:
        return default


def mac(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    hexdigits = "".join(ch for ch in value.lower() if ch in "0123456789abcdef")
    if len(hexdigits) != 12:
        return None
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def ipv4(value: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        return None


def dns_name(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def version(status: dict[str, Any]) -> str | None:
    v = str(status.get("version") or "").strip()
    return v.removeprefix("v") or None


def own_ips(status: dict[str, Any], host: str) -> list[str]:
    """Addresses AdGuard Home answers DNS on, and the one Omini reaches it at."""
    out: list[str] = []
    for value in [host, *(status.get("dns_addresses") or [])]:
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        if str(ip) not in out:
            out.append(str(ip))
    return out


def rewrites(c: Client) -> list[dict[str, Any]]:
    rows = c.get("/control/rewrite/list")
    return [r for r in rows or [] if isinstance(r, dict)]


def records(rows: list[dict[str, Any]]) -> list[DnsRecord]:
    """The rewrites that are local names: an exact name answered with an IPv4
    address (wildcards, CNAMEs and IPv6 answers are left out)."""
    out: dict[tuple[str, str], DnsRecord] = {}
    for r in rows:
        if r.get("enabled") is False:
            continue
        name, ip = dns_name(r.get("domain")), ipv4(r.get("answer"))
        if not name or not ip or "*" in name:
            continue
        out[(name, ip)] = DnsRecord(name=name, ip=ip)
    return [out[k] for k in sorted(out)]


def answer_ips(row: dict[str, Any]) -> list[str]:
    """The A and AAAA addresses of an answer (a blocked one's 0.0.0.0 or :: is
    not an address anyone connects to)."""
    out = []
    for a in row.get("answer") or []:
        if not isinstance(a, dict) or a.get("type") not in ("A", "AAAA"):
            continue
        try:
            ip = ipaddress.ip_address(str(a.get("value")).strip())
        except ValueError:
            continue
        if not ip.is_unspecified:
            out.append(str(ip))
    return out


def lookups(rows: list[Any]) -> list[Any]:
    """One lookup per client and name, newest first (the log's order), with
    every address it was answered."""
    found: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        client = str(row.get("client") or "").strip()
        domain = dns_name((row.get("question") or {}).get("name"))
        if not client or not domain:
            continue
        key = (client, domain)
        if key not in found:
            if len(found) >= MAX_LOOKUPS:
                continue
            found[key] = []
        found[key] += [ip for ip in answer_ips(row) if ip not in found[key]]
    return [DnsLookup(client=c, domain=d, answers=ips or None) for (c, d), ips in found.items()]


def recent_lookups(c: Client) -> list[Any] | None:
    """The query log's recent lookups; none with an older Omini, a log that
    is off, or a failed read (they only name where devices go)."""
    if DnsLookup is None or "dns_lookups" not in Device.model_fields:
        return None
    try:
        data = c.get(f"/control/querylog?limit={QUERYLOG_LIMIT}") or {}
        return lookups(data.get("data") or []) or None
    except Exception as e:
        log.debug("query log not read: %s", e)
        return None


def when(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else None


def leases(dhcp: dict[str, Any]) -> list[DhcpLease]:
    out = []
    for row in dhcp.get("leases") or []:
        m, ip = mac(row.get("mac")), ipv4(row.get("ip"))
        if m and ip:
            out.append(
                DhcpLease(
                    ip=ip,
                    mac=m,
                    hostname=row.get("hostname") or None,
                    expires_at=when(row.get("expires")),
                )
            )
    return out


def reservations(dhcp: dict[str, Any]) -> list[DhcpReservation]:
    out = []
    for row in dhcp.get("static_leases") or []:
        m, ip = mac(row.get("mac")), ipv4(row.get("ip"))
        if m and ip:
            out.append(DhcpReservation(mac=m, ip=ip, name=row.get("hostname") or None))
    return out


def pool(dhcp: dict[str, Any], used: list[DhcpLease]) -> DhcpPool | None:
    v4 = dhcp.get("v4") or {}
    start, end = ipv4(v4.get("range_start")), ipv4(v4.get("range_end"))
    gw, mask = ipv4(v4.get("gateway_ip")), ipv4(v4.get("subnet_mask"))
    if not start or not end:
        return None
    lo, hi = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
    if hi < lo:
        return None
    network = f"{start}-{end}"
    if gw and mask:
        with contextlib.suppress(ValueError):
            network = str(ipaddress.IPv4Network(f"{gw}/{mask}", strict=False))
    in_range = sum(1 for lease in used if lo <= ipaddress.IPv4Address(lease.ip) <= hi)
    return DhcpPool(network=network, total=int(hi) - int(lo) + 1, used=in_range)


def collect(cfg: Config) -> list[Device]:
    c = client_from(cfg)
    try:
        return [read(c, host_of(cfg))]
    finally:
        c.close()


def read(c: Client, host: str) -> Device:
    status = c.get("/control/status") or {}
    if not isinstance(status, dict) or "version" not in status:
        raise PluginError("the address did not answer like AdGuard Home (no /control/status)")
    rows = rewrites(c)
    # Builds without a DHCP server (or a disabled one) report no leases.
    dhcp = optional(lambda: c.get("/control/dhcp/status"), None) or {}
    dhcp_on = bool(dhcp.get("enabled"))
    services = [
        Service(
            name="DNS",
            description="AdGuard Home DNS server",
            running=bool(status.get("running", True)),
            enabled=True,
        )
    ]
    if dhcp:
        services.append(
            Service(
                name="DHCP",
                description="AdGuard Home DHCP server",
                running=dhcp_on,
                enabled=dhcp_on,
            )
        )
    dev = Device(
        key=host,
        name="AdGuard Home",
        host=host,
        role="server",
        vendor="AdGuard",
        model="AdGuard Home",
        os_version=version(status),
        ips=own_ips(status, host) or None,
        dns_records=records(rows),
        services=services,
    )
    if (seen := recent_lookups(c)) is not None:
        dev.dns_lookups = seen
    if dhcp_on:
        got = leases(dhcp)
        dev.dhcp_leases = got
        dev.dhcp_reservations = reservations(dhcp)
        p = pool(dhcp, got)
        dev.dhcp_pools = [p] if p else None
        domain = dns_name(dhcp.get("local_domain_name"))
        dev.dns_domain = domain or None
    return dev


def test(cfg: Config) -> str:
    c = client_from(cfg)
    try:
        status = c.get("/control/status") or {}
        if not isinstance(status, dict) or "version" not in status:
            raise PluginError("the address did not answer like AdGuard Home (no /control/status)")
        rows = rewrites(c)
    finally:
        c.close()
    v = version(status)
    return f"Connected to AdGuard Home{' ' + v if v else ''}, {len(records(rows))} local names"


# -- changes --


def value_of(change: Change) -> dict[str, Any]:
    v = change.value
    if not isinstance(v, dict):
        raise PluginError(f"{change.kind}: the value must be an object")
    return v


def wanted_name(v: dict[str, Any]) -> str:
    name = dns_name(v.get("name"))
    if not name or "*" in name or " " in name:
        raise PluginError("a local DNS name is required, e.g. nas.home.arpa")
    return name


def same(rows: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    return [r for r in rows if dns_name(r.get("domain")) == name]


def entry(r: dict[str, Any]) -> dict[str, Any]:
    """A rewrite as the add/delete endpoints take it."""
    return {"domain": r.get("domain"), "answer": r.get("answer")}


def set_name(c: Client, name: str, ip: str) -> None:
    mine = same(rewrites(c), name)
    if len(mine) == 1 and ipv4(mine[0].get("answer")) == ip and mine[0].get("enabled") is not False:
        return
    new = {"domain": name, "answer": ip}
    if not mine:
        c.post("/control/rewrite/add", new)
        return
    first, rest = mine[0], mine[1:]
    try:
        c.put("/control/rewrite/update", {"target": entry(first), "update": new})
    except NotFound:
        # Versions before the update endpoint: delete, then add (and put it back on failure).
        c.post("/control/rewrite/delete", entry(first))
        try:
            c.post("/control/rewrite/add", new)
        except PluginError:
            c.post("/control/rewrite/add", entry(first))
            raise
    for r in rest:
        c.post("/control/rewrite/delete", entry(r))


def delete_name(c: Client, name: str) -> None:
    for r in same(rewrites(c), name):
        c.post("/control/rewrite/delete", entry(r))


def apply(cfg: Config, change: Change) -> list[Device]:
    kind = change.kind if isinstance(change.kind, str) else change.kind.value
    v = value_of(change)
    c = client_from(cfg)
    try:
        if kind == "dns.set":
            name, ip = wanted_name(v), ipv4(v.get("ip"))
            if not ip:
                raise PluginError("dns.set: the address must be an IPv4 address")
            set_name(c, name, ip)
            got = same(rewrites(c), name)
            if [ipv4(r.get("answer")) for r in got] != [ip]:
                raise PluginError(f"AdGuard Home did not keep {name} → {ip}")
            log.info("AdGuard Home: %s set", name)
        elif kind == "dns.delete":
            name = wanted_name(v)
            delete_name(c, name)
            if same(rewrites(c), name):
                raise PluginError(f"AdGuard Home still answers {name}")
            log.info("AdGuard Home: %s deleted", name)
        else:
            raise PluginError(f"AdGuard Home does not support the change {kind}")
        return [read(c, host_of(cfg))]
    finally:
        c.close()


# -- backup --


def without(d: Any, keys: set[str]) -> Any:
    return {k: v for k, v in d.items() if k not in keys} if isinstance(d, dict) else d


def filters(status: dict[str, Any]) -> dict[str, Any]:
    out = dict(status)
    for key in ("filters", "whitelist_filters"):
        rows = [without(f, LIVE_FILTER) for f in out.get(key) or []]
        out[key] = sorted(rows, key=lambda f: (str(f.get("url")), str(f.get("name"))))
    return out


def settings(c: Client) -> dict[str, Any]:
    """What defines AdGuard Home's behaviour, without live state."""
    out: dict[str, Any] = {
        "status": without(c.get("/control/status") or {}, LIVE_STATUS),
        "rewrites": sorted(
            (entry(r) | ({"enabled": r["enabled"]} if "enabled" in r else {}) for r in rewrites(c)),
            key=lambda r: (str(r["domain"]), str(r["answer"])),
        ),
    }
    if (info := optional(lambda: c.get("/control/dns_info"), None)) is not None:
        out["dns"] = info
    if (f := optional(lambda: c.get("/control/filtering/status"), None)) is not None:
        out["filtering"] = filters(f)
    if (cl := optional(lambda: c.get("/control/clients"), None)) is not None:
        # Persistent clients only: the "auto" ones are what it saw lately.
        out["clients"] = sorted(cl.get("clients") or [], key=lambda x: str(x.get("name")))
    if (dhcp := optional(lambda: c.get("/control/dhcp/status"), None)) is not None:
        conf = without(dhcp, {"leases"})
        conf["static_leases"] = sorted(
            conf.get("static_leases") or [], key=lambda x: (str(x.get("ip")), str(x.get("mac")))
        )
        out["dhcp"] = conf
    if (access := optional(lambda: c.get("/control/access/list"), None)) is not None:
        out["access"] = access
    return out


def backup(cfg: Config) -> list[ConfigBackup]:
    c = client_from(cfg)
    try:
        data = settings(c)
    finally:
        c.close()
    content = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
    return [ConfigBackup(device=host_of(cfg), format="json", content=content + "\n")]
