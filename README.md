# omini-plugin-adguard

[Omini](https://github.com/riccardoalv/omini) plugin for **AdGuard Home**,
through its web API (`/control/...`). Omini uses it as the DNS server of a
network: the local names Omini gives to devices with a fixed address go here
when the network's DHCP hands out AdGuard Home as its DNS server.

## What it reads

| Data | Used for |
|---|---|
| Version, the addresses it answers DNS on | The server on the map (vendor AdGuard, model AdGuard Home), merged by address with the machine it runs on |
| DNS rewrites whose answer is an IPv4 address | The network's local names (`nas.home.arpa → 192.168.1.20`); wildcards, CNAMEs and IPv6 answers are left out |
| DHCP server, when it is on: leases, static leases, range, local domain | Clients and their addresses, fixed addresses, pool usage |
| DNS and DHCP running | Services in the device's panel |
| The query log's last 1000 entries: which client asked for which name, and the A/AAAA addresses answered | Naming where devices go in traffic flows (address → name) |

The query log gives at most 500 lookups, one per client and name (newest
first), with every address it was answered (a blocked answer's `0.0.0.0` is
left out). Omini uses them only to name the destinations of traffic flows and
keeps them in memory, never on disk. With the query log off, or when it cannot
be read, the rest is collected as usual; an Omini older than 1.6 does not ask
for it.

## What it changes

| Change | What it does |
|---|---|
| `dns.set` `{name, ip}` | Adds the rewrite `name → ip`; a rewrite with the same name and another address is updated (never duplicated), extra ones with that name are removed. Read again to check it took. |
| `dns.delete` `{name}` | Removes every rewrite with that name. Read again to check. |

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
| GET | `/control/dns_info`, `/control/filtering/status`, `/control/clients`, `/control/access/list` | Backup |

## Not verified on hardware

The plugin follows AdGuard Home's `openapi.yaml` (v0.107) and was tested
against a fake API and the Omini devnet emulator only:

- `PUT /control/rewrite/update` with `{target, update}` (newer versions); a
  404/405 falls back to delete + add.
- The `enabled` field of rewrites (recent versions): disabled ones are skipped.
- `local_domain_name` in `/control/dhcp/status`: read as the local domain when
  present; otherwise the domain is left empty.
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
