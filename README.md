# go-tun

Gateway split-tunnel for client traffic: clients keep local LAN on-link and send non-local traffic to **gotun**; gotun sends Russian destinations **direct** and everything else via a **WireGuard** hop outside Russia.

## Purpose

- Clients are intentionally dumb: no geo logic.
- `gotun` owns the RU / non-RU decision and configures the **Linux kernel** datapath (nftables + policy routing + WireGuard).
- Userspace only reconciles desired state; packets are not proxied in userspace.

## Architecture

```
Client --LAN on-link--> local peers
Client --default------> gotun
                          |-- dst in ru_nets --> direct
                          |-- else          --> wg0 --> exit (outside RU)
```

Control flow:

1. Build a `Policy` (direct prefixes, tunnel endpoint, LANs, mark/table, fail mode).
2. Compile to declarative `DesiredKernelState` (no shell-op ordering in the model).
3. Reconcile owned Linux objects: sysctl → nftables → WireGuard → ip rules/routes.

Gotun does **not** masquerade by default; the exit peer should accept the client LAN via WireGuard AllowedIPs (and may SNAT toward foreign destinations).

## Why MaxMind Country prefixes

Routing uses MaxMind-style country classification (`country_iso_code`). For the kernel we materialize **CIDRs** into an nftables set instead of per-packet MMDB lookups.

Optional local GeoIP2/GeoLite2 City or Country MMDB at `data/geo/GeoIP2-City.mmdb` (gitignored — licensed MaxMind data must not be committed):

```bash
make fetch-prefixes     # uses local MMDB if present → prefixes.txt
gotun fetch -mmdb data/geo/GeoIP2-City.mmdb -country RU -out prefixes.txt
```

Without a local MMDB: GeoLite2-Country CSV download (`MAXMIND_LICENSE_KEY` required).

Unit tests use small CSV fixtures under `testdata/prefixes/`; large-set extract/compile/render runs when `data/geo/GeoIP2-City.mmdb` is present (skip otherwise). Real nftables load of the full RU set:

```bash
make test-large-set     # GOTUN_LARGE_SET=1; Docker --network none; needs local MMDB + gotun:lab
```


## Fail-closed + endpoint exclusion

Table **100 always** ends with a terminal **blackhole** default (high metric). When the tunnel is up, a lower-metric `default dev wg0` is preferred. If `wg0` disappears **without** a control-plane reapply, marked (non-RU) traffic still hits the blackhole and does **not** fall through RPDB into the ISP/`main` table. `-tunnel-up=false` installs only the blackhole. RU (unmarked) traffic continues on the main table.

The WireGuard **underlay endpoint IP** is excluded from marking so handshake/path cannot recurse into `wg0`.

## Why nftables

Greenfield choice: one rule system, native interval sets, and **single-transaction** table replacement via one `nft -f` batch (delete+recreate owned table atomically). Not an iptables+ipset stack.

## Ownership

Reconciler only touches objects it owns:

- nftables table **`inet gotun`**
- routing table **`100`** and ip rule priority **`100`**
- WireGuard interface from policy (default `wg0`) when managed

`gotun clear` deletes those owned objects only.

## Idempotency

Re-applying the **same** `Policy` must be a **semantic no-op** (no meaningful kernel changes). Equality is by table/set/rule/route/sysctl content — not nft handle numbers.

## Partial failure

v1 has **no** cross-subsystem transaction (nft + netlink + WireGuard). On mid-apply failure the command exits non-zero; some owned objects may already be updated. Recovery is a successful full `gotun apply`.

## DNS (v1)

Classification is **IP-destination based**. Whatever address the client’s resolver returns is what gotun classifies. DNS interception / split DNS is out of scope for v1 (see TODO).

## IPv6 (v1)

No IPv6 split routing. Lab and apply disable/drop IPv6 so it cannot bypass policy. Full IPv6 support is TODO.

## Host isolation

**Host network namespace is never modified** by labs or tests. Integration tests use disposable Docker **bridge** networks (`--internal`), never `--network=host`. Only the Docker API control plane runs on the host.

## Lab topology

Outbound split lab containers: `client`, `gotun`, `exit`, `ru-dest`, `foreign-dest`.

| Path | Expected |
|------|----------|
| client → RU IP | via gotun direct (not wg0/exit) |
| client → foreign IP | via gotun wg0 → exit |
| WG down (no reapply) | foreign fails; RU works |
| endpoint IP | not via wg0 |

## LAN / Pi deployment

Typical home install: Pi on the LAN; router port-forwards **only** the inbound clients WireGuard UDP port to the Pi; your PC uses the Pi’s **LAN IP** as gateway (not the public IP).

Invariants (proven by `TestLANDeploy_PortForwardHomeIsolation`):

1. WAN peers reach gotun only via the forwarded WG port.
2. Home devices use gotun’s LAN address directly.
3. Tunneled WAN peers cannot reach home-LAN destinations (`iifname "wg-clients" ip daddr @home_nets drop` in `inet gotun`).

Apply with a second config for the clients listen interface:

```bash
gotun apply -prefixes prefixes.txt -endpoint <exit-underlay> \
  -lan 192.168.1.0/24 \
  -wg-config wg0.conf \
  -wg-clients-config wg-clients.conf \
  -tunnel-up true
```

`-lan` feeds both mark exclusions and the `home_nets` isolation set.

## Deployment topology (high fidelity)

Integration hierarchy:

```text
topology_test.go       → kernel/policy correctness (fast)
lan_deploy_test.go     → home-router port-forward + LAN isolation
deploy_topo_test.go    → RU vs external Internet, egress identity
```

`TestDeployTopo_EgressIdentity` places the Pi **only** on home LAN. A remote client on RU Internet reaches the Pi via home-router DNAT. The physical RU↔external uplink remains; the test proves path choice by **source identity** at destinations (`labhttp` `GET /peer` from `RemoteAddr`):

- RU destination sees **home-router WAN**
- non-RU destination sees **remote-hop**

## Build & test

Requires Go **1.26+**. Integration and large-set tests talk to the Docker **daemon** via the Engine API (socket / `DOCKER_HOST`); the `docker` CLI is only needed for `make docker-build`.

```bash
make build               # bin/gotun
make test                # unit tests only (large MMDB compile/render if MMDB present)
make docker-build        # gotun:lab image (docker CLI)
make test-integration    # GOTUN_INTEGRATION=1; isolated Docker nets
make test-large-set      # GOTUN_LARGE_SET=1; full RU set → nft in Docker (--network none)
make fetch-prefixes      # prefer local data/geo/*.mmdb; else CSV + MAXMIND_LICENSE_KEY
make clean
```

CLI:

```bash
gotun fetch -mmdb data/geo/GeoIP2-City.mmdb -out prefixes.txt -country RU
gotun fetch -out prefixes.txt -country RU   # CSV download; needs MAXMIND_LICENSE_KEY
gotun apply -prefixes prefixes.txt -endpoint 10.20.0.2 -lan 10.10.0.0/24 -wg-config wg0.conf -tunnel-up true
gotun apply ... -wg-clients-config wg-clients.conf   # optional inbound clients iface + home isolation
gotun clear
```
## Out of scope (v1)

- Userspace SOCKS/proxy
- IPv6 split routing
- DNS interception
- iptables+ipset backend
- Fail-open on tunnel loss
- Cross-subsystem rollback
- Applying rules on the host netns

## TODO / future improvements

Do **not** implement these until the v1 core (build, unit tests, integration invariants) is green:

- [ ] **IPv6 support** — `ru_nets6`, mark + policy routing; stop blanket disable/drop
- [ ] **DNS** — forced resolver / split DNS so DNS cannot bypass RU/non-RU policy
- [ ] **Fail-open mode** — optional ISP fallback when WG is down
- [ ] **Prefix source refresh** — scheduled/atomic MaxMind updates in production
- [ ] **Observability** — counters for marked vs direct, set size, reconcile errors
- [ ] **Multi-exit / multi-peer WireGuard**
- [ ] **Stronger apply transactions** — cross-subsystem rollback if needed
