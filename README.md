# omini-plugin-adguard

[Omini](https://github.com/riccardoalv/omini) plugin for **AdGuard Home**,
through its web API (`/control/...`). Omini uses it as the DNS server of a
network: the local names Omini gives to devices with a fixed address go here
when the network's DHCP hands out AdGuard Home as its DNS server.

## What it reads

| Data | Used for |
|---|---|
| Version, the addresses it answers DNS on | The server on the map (vendor AdGuard, model AdGuard Home), merged by address with the machine it runs on |
| The MAC of its network interface (`/control/dhcp/interfaces`): the one holding the address Omini reaches it at (IPv4 or IPv6), else the first other one with an address | The device's key, so it merges with the machine it runs on, as Pi-hole does; without it (no DHCP support in the build, or a refused read) the address is the key |
| DNS rewrites whose answer is an IPv4 or IPv6 address | The network's local names (`nas.home.arpa → 192.168.1.20`, `nas.home.arpa → fd00::20`); wildcards, CNAMEs and blocking answers (`::`) are left out. IPv6 answers are only read: `dns.set` and `dns.delete` manage the IPv4 ones |
| DHCP server, when it is on: leases (IPv4 and DHCPv6; link-local addresses left out), static leases, range (IPv4), local domain | Clients and their addresses, fixed addresses, pool usage |
| DNS and DHCP running | Services in the device's panel |
| The query log's last 1000 entries: which client asked for which name, and the A/AAAA addresses answered | Naming where devices go in traffic flows (address → name) |

The query log gives at most 500 lookups, one per client and name (newest
first), with every address it was answered (`0.0.0.0` and `::` left out),
without blocked queries (a `Filtered...` reason: nothing was reached) and
clients without an address. Omini uses them only to name the destinations of
traffic flows and keeps them in memory, never on disk. With the query log off,
or when it cannot be read, the rest is collected as usual; an Omini older than
1.6 does not ask for it.

Omini never asks AdGuard Home to check for updates (`/control/version.json`
is not called), so pending updates are not shown.

Since this version the device's key is its MAC instead of the address typed
in the form: an AdGuard Home added before gets a new node in Omini once, and
the history of its old node (keyed by the address) is not carried over.

## What it changes

| Change | What it does |
|---|---|
| `dns.set` `{name, ip}` | Adds the rewrite `name → ip`; a rewrite with the same name and another IPv4 address is updated (never duplicated), extra IPv4 ones with that name are removed; a disabled one is switched on. IPv6 answers and CNAMEs of the name are left alone. Read again to check it took. |
| `dns.delete` `{name}` | Removes the enabled rewrites of that name answered with an IPv4 address (IPv6 answers, CNAMEs and disabled ones stay). Read again to check. |

AdGuard Home saves its configuration by itself: there is no separate save step.
Rewrites have no description field, so the ones Omini made are not marked.

## Backups

The configuration as sorted JSON, without live state (so two backups differ
only when the configuration changed): `/control/status` without `running`,
`start_time`, the protection timer and the listening addresses;
`/control/dns_info`; `/control/filtering/status` without the lists' rule counts
and update dates; the rewrites; the persistent clients (not the ones it only
saw); `/control/dhcp/status` without the leases; `/control/access/list`.
AdGuard Home's API never returns its users' password hashes.

## Account

AdGuard Home has one kind of user: the users of its web interface (`users:` in
`AdGuardHome.yaml`), all with full access. Use one of them, or add a user for
Omini to `AdGuardHome.yaml` (`name` and a bcrypt `password` hash, e.g.
`htpasswd -B -C 10 -n omini`) and restart AdGuard Home. That user can read the
query log too (AdGuard Home has no read-only role). Requests use HTTP basic
authentication; prefer HTTPS when AdGuard Home has it.

## Endpoints

| Method | Path | For |
|---|---|---|
| GET | `/control/status` | Version, DNS addresses, test |
| GET | `/control/rewrite/list` | Local names |
| POST | `/control/rewrite/add` | `dns.set` (new name) |
| PUT | `/control/rewrite/update` | `dns.set` (same name, other address); older versions: delete + add |
| POST | `/control/rewrite/delete` | `dns.delete`, duplicates |
| GET | `/control/querylog?limit=1000` | Recent DNS lookups |
| GET | `/control/dhcp/status` | DHCP leases, static leases, range; backup |
| GET | `/control/dhcp/interfaces` | The MAC (the device's key) |
| GET | `/control/dns_info`, `/control/filtering/status`, `/control/clients`, `/control/access/list` | Backup |

## Not verified on hardware

The plugin follows AdGuard Home's `openapi.yaml` (v0.107) and was tested
against a fake API and the Omini devnet emulator only:

- `PUT /control/rewrite/update` with `{target, update}` (newer versions); a
  404/405 falls back to delete + add.
- The `enabled` field of rewrites (recent versions): disabled ones are skipped;
  `dns.set` on a name whose rewrite is disabled sends `enabled: true` in the
  update, and checks that it is on.
- `local_domain_name` in `/control/dhcp/status`: read as the local domain when
  present; otherwise the domain is left empty.
- `/control/dhcp/interfaces` as a map of `NetInterface` (`hardware_address`,
  `flags`, `ipv4_addresses`, `ipv6_addresses`); loopback interfaces and
  those without a MAC are skipped.
- The 401 (or 403) answer for wrong credentials.
- The query log's `client` as the client's address (it is the address unless
  `anonymize_client_ip` is on, then a partly zeroed address).

## Development

```bash
uv run pytest -q          # tests (the SDK comes from ../omini/sdk/python)
uv run ruff check . && uv run ruff format --check .
```

## License

MIT
