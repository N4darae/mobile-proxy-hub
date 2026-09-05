# INSTALL.md — putting dongled on a machine

Read `HARDWARE.md` first and buy the right hub. Everything below assumes you already have hardware
that passes `dongled probe --experiment a6`.

Nothing in this document is automated behind your back. `dongled bootstrap` writes files and prints a
list of commands; **it never creates an account, changes a sysctl, or restarts a service.** Those
steps are yours, and each one is listed with what it does and how to undo it.

---

## 1. One host or two

There are two roles:

- **panel host** — runs `dongled serve`, the SQLite database, and nginx in front of the web UI.
- **farm host** — has the USB hubs, the dongles, the `dgNN` interfaces, the `ip rule`s, the nft table
  and the 150 `dongled-proxy@` instances.

**They may be the same machine, and for a first deployment they should be — but only if that machine
has USB ports a human being can physically reach.**

That is not a figure of speech. Recovering a wedged dongle sometimes means unplugging it. If your
"server" is a VPS in a datacentre you have never visited, it cannot be the farm host, no matter how
good the rest of it is. A VPS can be the panel host, with a machine in an office or a colo cage you
can walk to as the farm host.

This release ships the local case: one binary, one database, panel and farm together. There is no
remote agent and no `agent_url`. If you split the roles later, the split is at the HTTP API, and the
panel host holds the database.

The farm host is identified by the file `/etc/dongled/FARM`. `dongled enroll` refuses to run without
it, because enrollment rewrites `ip rule`s, `systemd-networkd` files and nft sets in the root network
namespace and that is not something to do on the wrong machine by accident.

---

## 2. Prepare the operating system

Debian 13, Ubuntu 24.04, or anything else with **kernel ≥ 6.2**. See `HARDWARE.md` §4.2.

```
sudo apt update
sudo apt install nftables iproute2 conntrack usbutils uhubctl nginx
uname -r                                     # must be 6.2 or newer
```

Give the machine a **static** IPv4 address. `ip -4 -o addr show` must not print `dynamic` or a finite
`valid_lft` for the address you intend to sell through. This is checked, and it is the failure that
takes the entire farm dark with no useful log line.

Disable ModemManager if nothing else on the box needs it:

```
sudo systemctl disable --now ModemManager
```

If you cannot, the udev rule installed in step 4 keeps it away from Huawei devices instead.

Run the read-only check before installing anything:

```
./deploy/preflight.sh --public-ip 203.0.113.7
```

It writes nothing. Fix whatever it reports before continuing.

---

## 3. Build

```
cd src
make build                     # -> bin/dongled
make web-install && make web   # builds the SPA into internal/webui/dist
make build                     # rebuild so the SPA is embedded
```

3proxy is pinned to commit `122ca26249aaaac9156e0805891555c70e19f2b3`. Build exactly that commit —
not the `0.9.8` tag, which was re-submitted and may point somewhere else:

```
git clone https://github.com/z3APA3A/3proxy /tmp/3proxy
cd /tmp/3proxy
git checkout 122ca26249aaaac9156e0805891555c70e19f2b3
make -f Makefile.Linux WOLFSSL_CHECK=false OPENSSL_CHECK=false PCRE_CHECK=false PAM_CHECK=false
```

Install both binaries:

```
sudo install -D -m 0755 bin/dongled            /usr/local/bin/dongled
sudo install -D -m 0755 /tmp/3proxy/bin/3proxy /usr/local/lib/dongled/3proxy
sudo mkdir -p /usr/local/share/dongled
sudo cp -r deploy /usr/local/share/dongled/deploy
sudo cp -r docs  /usr/local/share/dongled/docs
```

`dongled bootstrap` records the SHA-256 of the 3proxy binary next to it, and `preflight` compares
that digest on every start. A rebuilt or replaced binary turns the check red until you re-run
bootstrap, which is the intent.

---

## 4. Lay down the files

Rehearse into a scratch directory first. This writes nothing to the real filesystem:

```
dongled bootstrap --root /tmp/rehearse --apply --source /usr/local/share/dongled/deploy
find /tmp/rehearse -type f
```

Read what it produced. When you are happy:

```
sudo dongled bootstrap --apply --force
```

`--force` is required whenever `--root` is empty; it is there so that a mistyped command cannot write
into `/etc` on a machine you did not mean to touch.

That places:

| file | purpose |
|---|---|
| `/etc/systemd/system/dongled.service` | the controller |
| `/etc/systemd/system/dongled-proxy@.service` | the 3proxy instance template, rendered by the code that also renders the configs |
| `/etc/sysusers.d/dongled.conf` | group `dongled` gid 6100, users `px01`..`px150` uid 6101..6250 |
| `/etc/sysctl.d/60-dongled.conf` | `conf.default.rp_filter=2`, `ip_forward=0`, conntrack sizing |
| `/etc/udev/rules.d/99-dongled-mm-ignore.rules` | keeps ModemManager and NetworkManager off the dongles |
| `/etc/systemd/networkd.conf.d/dongled.conf` | `ManageForeignRoutingPolicyRules=no` |
| `/etc/nginx/conf.d/dongled-limits.conf` | rate limit zones and the SSE server-block template |
| `/etc/iproute2/rt_tables.d/dongled.conf` | names for route tables 1001-1150 |
| `/etc/dongled/FARM` | marks this host as the farm |

Re-running bootstrap is safe. It compares content and prints `keep` for anything already correct.

Nothing under `/etc/nginx/nginx.conf` is touched, ever.

---

## 5. The steps bootstrap will not take for you

Run these in order. Each says what it changes.

```
# 5.1 Create the accounts. Reversible with userdel/groupdel.
sudo systemd-sysusers
getent group dongled                       # must print dongled:x:6100:
getent passwd px01                         # must print uid 6101

# 5.2 Apply the sysctls. Reversible by deleting the drop-in and re-running.
sudo sysctl --system
sysctl net.ipv4.conf.all.rp_filter         # must be 2 (the distro already sets this)
sysctl net.ipv4.ip_forward                 # must be 0

# 5.3 Load the udev rules. Affects Huawei devices only.
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb --subsystem-match=net

# 5.4 Pick up ManageForeignRoutingPolicyRules=no.
#     THIS RESTARTS NETWORKING. Do it from the console or inside tmux, never
#     from the ssh session you need to keep.
sudo systemctl restart systemd-networkd
```

### 5.5 The key ceremony

```
sudo dongled bootstrap-kek
```

This writes `/etc/dongled/kek.cred`, mode 0600. It is the only thing that can decrypt the proxy
passwords stored in the database.

**Copy it off this machine now, before enrolling anything, and verify the copy is readable.** A
database backup without this file is worthless and there is no recovery path. Do not re-run
`bootstrap-kek` afterwards; overwriting the key makes every stored password permanently unreadable,
which is why the command refuses without `--force`.

### 5.6 Ingress

If a firewall is in the way, open the proxy ports:

```
sudo ufw allow 21001:21150/tcp comment 'dongled socks'
sudo ufw allow 22001:22150/tcp comment 'dongled http'
```

Only on the farm host, and only if you actually run ufw. The panel port `8788` and the metrics port
`9788` bind `127.0.0.1` and must **not** be opened.

---

## 6. Start the controller

```
sudo tee /etc/dongled/dongled.env >/dev/null <<'EOF'
DONGLED_PUBLIC_HOST=203.0.113.7
DONGLED_NODE_ID=farm1
DONGLED_NETCFG=linux
DONGLED_DEVICE=hilink
DONGLED_PROXY=systemd
DONGLED_FW=nft
EOF

sudo systemctl daemon-reload
sudo dongled preflight --public-host 203.0.113.7
```

Everything except `recent_backup` should be green. `nft_table` stays red until the controller has
built the table once; start it and check again:

```
sudo systemctl enable --now dongled
sudo systemctl status dongled
sudo dongled preflight --public-host 203.0.113.7
```

`dongled.service` runs its own fatal preflight as `ExecStartPre`, so a red fatal check prevents
startup rather than producing a half-working farm.

### A note on the command line

Global flags and subcommand flags mix freely, in any order, with no separator:

```
dongled preflight --public-host 203.0.113.7 --fatal-only --json
dongled enroll --public-host 203.0.113.7 --slot 3
dongled probe --experiment a3 --rounds 20 --out docs/OPERATIONS.md
```

`--public-host`, `--node-id`, `--db`, `--device`, `--netcfg`, `--proxy` and `--fw` are global and
accepted by every subcommand; the rest belong to the subcommand you named. `dongled <command> -h`
lists both sets together. Single-dash spellings (`-slot 3`) work too, as they do for any Go program.

---

## 7. nginx

Copy the `server` block out of `/etc/nginx/conf.d/dongled-limits.conf` — it is in a comment there —
into your own site configuration, add your certificates, then:

```
sudo nginx -t && sudo systemctl reload nginx
```

Always `reload`, never `restart`.

The `location = /api/v1/events` block is not optional. Without `proxy_buffering off` the SSE stream
that drives the live panel is buffered forever, the page loads and then never updates, and **nothing
is logged on either side**. It gets found days later by a customer.

---

## 8. Enrol the first dongle

One dongle at a time. This is enforced, not advisory.

```
sudo dongled enroll --public-host 203.0.113.7 --slot 1 --carrier viettel
```

What it does, in order — the order is load-bearing:

1. Refuses if more than one interface holds a `192.168.8.0/24` address, or if any address is
   duplicated. Two factory-default dongles on one host is the most common way this goes wrong.
2. Disables the USB ports of the other un-provisioned slots for the duration of the session.
3. Waits for the new link and reads the **actual** `ID_PATH` with `udevadm`. On this class of host it
   looks like `pci-0000:00:14.0-usb-0:13.1:1.0`; xHCI is a PCI device, never `platform-*`. A `.link`
   file whose `Path=` does not match falls through to the MAC-matching rule, and E3372s share a MAC,
   so the second dongle fails to rename with `EEXIST` and nothing logs it. A path that is not observed
   is a hard error.
4. Stops if the dongle wants a login, and tells you to turn "Require login" off in its web UI.
5. Stops unless the SIM reports 257 (ready) or 258 (PIN disabled).
6. Reads IMEI/ICCID/IMSI/firmware and takes the slot.
7. Writes `.link` and `.network` and reloads — **before** touching DHCP, so a re-enumeration cannot
   rename the interface halfway through.
8. Moves the LAN to `192.168.10N.1`, sending the full object including the DHCP pool inside the new
   subnet. A timeout here usually means it **worked**; the device stops answering at the old address.
9. Sets `MaxIdelTime=0` and reads it back. Skipping this makes every idle proxy die after five
   minutes, which then looks like a rotation bug.
10. Adds the firewall entry, allocates ports, creates the proxy, starts the instance.
11. Re-enables the other USB ports.

Any failure rolls back, so a slot is never left half-provisioned.

At the end it prints the credentials and the sysfs path of the port it used. **Write the slot number
on that physical port now** — see `HARDWARE.md` §3.2.

Then repeat for the next stick. Take the first backup as soon as one proxy works:

```
sudo dongled backup
```

### 8.1 Verify from somewhere else

```
curl -x socks5h://USER:PASS@203.0.113.7:21001 -s --max-time 20 https://ifconfig.me
```

It must return the **dongle's** public address, not the host's. If it returns the host address the
policy routing is not in effect and every proxy you sell is the same IP. Run it from another machine;
a check from the farm host itself passes in exactly the failure mode you are looking for.

---

## 9. Uninstalling

```
sudo systemctl disable --now dongled 'dongled-proxy@*'
sudo nft delete table inet dongled            # NEVER nft flush ruleset
sudo rm -f /etc/systemd/system/dongled.service /etc/systemd/system/dongled-proxy@.service
sudo rm -f /etc/sysctl.d/60-dongled.conf /etc/udev/rules.d/99-dongled-mm-ignore.rules
sudo rm -f /etc/systemd/networkd.conf.d/dongled.conf /etc/nginx/conf.d/dongled-limits.conf
sudo rm -f /etc/iproute2/rt_tables.d/dongled.conf
sudo rm -f /etc/systemd/network/10-dongled-*.link /etc/systemd/network/70-dongled-*.network
sudo systemctl daemon-reload && sudo sysctl --system && sudo systemctl reload nginx
```

Remove the `ip rule`s the controller created, by priority — priority 900, and `1000+N` / `1500+N` per
slot. Do not flush the rule table; other software on the box owns rules too.

Keep `/var/lib/dongled` and `/etc/dongled/kek.cred` until you are certain you will not need the data.
Deleting the key makes every backup unreadable.

---

## 10. Developing on Windows or macOS

Everything above is the production install and stays Linux-only: nftables, netlink, network
namespaces, sysfs and systemd units do not exist anywhere else. But `dongled` is code, and a
contributor should not need a farm host, or even a Linux box, to build it, run `go test ./...`, or
poke at the panel API. Windows and macOS are supported **development** hosts; they are not, and will
not become, a target for the farm or panel roles above.

`go build ./...`, `go vet ./...` and `go test ./...` are clean for `GOOS=windows` and `GOOS=darwin` as
well as `GOOS=linux`; `make check` cross-builds and cross-vets all three so a regression fails the
build rather than showing up as a surprise on someone's laptop. See `CONVENTIONS.md` §8 for how the
platform split in the code is organised.

### 10.1 Running the daemon against the simulated farm

`dongled serve` runs on a non-Linux host against a simulated dongle farm — a fake network-config
backend and an in-process device backend that behaves like a small rack of dongles without any real
hardware. Only one variable is required:

- `DONGLED_PUBLIC_HOST` — the address the node treats as its own public IP. It must be a global unicast
  address, but for local development it does not need to be real or reachable.

The fake network-config backend and the simulated farm are already the defaults, and the state
directories default to a writable per-platform location, so nothing else has to be set.

On a **Linux** development box the defaults are the production paths instead — `/etc/dongled` and
`/var/lib/dongled` — because the same binary serves the farm role there. Point `DONGLED_ETC_DIR` and
`DONGLED_DB` at a scratch directory, otherwise `bootstrap-kek` and `serve` need root to write under
`/etc` and `/var/lib`.

Override any of these when you want to:

- `DONGLED_ETC_DIR` — the directory this instance uses for the state production keeps under
  `/etc/dongled`. Point it at a scratch directory when you want several instances side by side.
- `DONGLED_DB` — path to the SQLite database file.
- `DONGLED_PANEL_ADDR` / `DONGLED_METRICS_ADDR` — `host:port` pairs for the panel and the metrics
  server.
- `DONGLED_NETCFG` / `DONGLED_DEVICE` — `fake` and `sim` by default. The Linux-only `linux` and
  `hilink` backends refuse to start off Linux rather than half-working.
- `DONGLED_SIM_SLOTS` — how many simulated dongles the fake farm pretends to have.

Before the first `serve`, run the same key ceremony as §5.5, minus `sudo`:

```
dongled bootstrap-kek
```

It writes the key file inside `DONGLED_ETC_DIR` the same way it writes `/etc/dongled/kek.cred` in
production. Re-running it against an existing key refuses rather than overwriting, because a new key
makes every password already encrypted with the old one permanently unreadable; `--force` overrides
that, and on a scratch directory that is usually what you want.

Then `dongled serve` with the variables above starts the panel and the reconcile loop against the
simulated farm. `GET /api/v1/healthz` answers `200` once it is up.

### 10.2 What refuses, and how

Anything that needs a real Linux kernel facility — nftables (`--fw=nft`), netlink or networkd
(`--netcfg=linux`), systemd units (`--proxy=systemd`), sysfs or real USB enumeration
(`--device=hilink`, `dongled enroll`, most `dongled probe` experiments) — returns a plain
"unsupported on this platform" error on Windows and macOS instead of silently no-oping or pretending
to succeed. There is no fake systemd or fake nftables standing in for the real thing; the fake backends
that do exist (`netcfg=fake`, `device=sim`) are there to develop against, not to simulate the
production stack end to end. The netns integration suite (`make test-netns`) is Linux-only for the
same reason: it needs real network namespaces and root.

### 10.3 Cloning on Windows

A plain `git clone` aborts partway through checkout with `error: invalid path
'src/internal/enroll/testdata/sysfs/bus/usb/devices/1-0:1.0/uevent'`, leaving an empty working
tree. Ten captured Linux sysfs fixtures under `src/internal/enroll/testdata/sysfs/` have a `:` in
their path, which NTFS cannot represent. Clone with `--no-checkout` and a sparse-checkout that
excludes that directory instead:

```
git clone --no-checkout <repo-url>
cd huawei-API
git config core.protectNTFS false
git config core.sparseCheckout true
git config core.sparseCheckoutCone false
printf '/*\n!/src/internal/enroll/testdata/sysfs/\n' > .git/info/sparse-checkout
git checkout
```
