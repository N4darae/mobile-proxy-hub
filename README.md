# Open Proxy - Control your own proxy service

<a href="https://trendshift.io/repositories/108758?utm_source=trendshift-badge&utm_medium=badge&utm_campaign=badge-trendshift-108758" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/108758/daily?language=Go" alt="N4darae/huawei-API | Trendshift" width="250" height="55"/></a>
<a href="https://trendshift.io/repositories/108758?utm_source=trendshift-badge&utm_medium=badge&utm_campaign=badge-trendshift-108758" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/108758/weekly?language=Go" alt="N4darae/huawei-API | Trendshift" width="250" height="55"/></a>

This repo is a proxy service you can actually sell, the same kind of product as Bright Data or
Oxylabs. You run it yourself on 4G dongles.

Each customer owns their own proxies and gets their own API key. A key is scoped in three ways: to
one customer, to the specific proxies that customer owns, and to a set of permissions, so a key
that rotates an IP cannot read anything else and a status key cannot rotate. A customer can also be
given a single-purpose rotate link that works without any panel account.

In short: proxies in your own country, on your own SIMs.

![The proxy list: per-slot state, WAN address, signal and SIM quota](docs/screenshots/proxies.png)

## Network isolation

Every slot has its own routing table and policy rule, and an nftables table drops traffic leaving
through an interface it does not belong to. Traffic cannot go out the wrong SIM. This is handled to
a production standard, so it is not a problem you have to solve yourself.

## Security

Proxy passwords are encrypted at rest under a key file kept off the machine, so a database backup
alone does not expose them. Rotate links are revoked independently of the key that issued them.

![API keys, each scoped to a customer and to the proxies they own](docs/screenshots/api-keys.png)

## What you get

- One Linux host runs up to 150 dongles, one 3proxy instance per stick.
- SOCKS5 on 21001-21150, HTTP on 22001-22150.
- Rotation by cycling the SIM data session. `dongled probe --experiment a3` measures the change
  rate and the hold time your carrier needs.
- A web panel and an HTTP API over the same contract.

## Limits

The bottleneck is USB topology, not software. Each populated port draws about an amp, and the hub
needs per-port power switching to reboot one stick without cutting the others. See
`src/docs/HARDWARE.md`.

150 is the ceiling of the shipped address plan, not a licence. Each slot takes a /24 at
`192.168.<100+slot>.0`, which runs out at 155. Moving to `10.0.0.0/8` and widening the port and
rule-priority ranges goes further. The constants are in `src/internal/domain/slot.go`.

Windows and macOS build, vet and test the tree, and `dongled serve` runs there against a simulated
dongle farm. Off Linux, nftables, netlink, systemd and USB access refuse with an explicit error.
Production requires Linux with kernel 6.2 or newer.

## Start here

`src/docs/HARDWARE.md`, then `src/docs/INSTALL.md`.

Collect only what you are allowed to collect.
