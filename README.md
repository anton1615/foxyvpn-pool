# 🦊 foxyvpn-pool

**One shared token pool, many clients.** `foxyvpn-pool` turns
[foxyvpn](https://pypi.org/project/foxyvpn/) — the Local SOCKS5 proxy client
for the Mozilla VPN / Firefox VPN proxy service — from a single-machine,
single-client tool into a small **multi-client service for your trusted
network**: every client gets its own dedicated Mozilla VPN exit behind a
stable port, delivered as 🧾 mihomo subscription nodes and controlled over a
⚙️ HTTP API.

> Unofficial community software. Not affiliated with or endorsed by Mozilla.
> Only use it with accounts and a subscription you are authorized to use, in
> accordance with Mozilla's terms of service.

## ✨ Highlights

- 🖥 **One pool, N clients** — every foxyvpn instance draws from the same
  pre-provisioned token pool on the host
- 🚪 **A stable port per client** — public ports come from a monotonic
  counter persisted in the state DB, so subscription URLs never go stale
- ♻️ **Dynamic quota refills** — remaining quota is polled from Guardian's
  `X-Quota-*` headers; an instance whose token set runs dry is moved to a
  fresh one **without dropping a single client connection**
- 🌍 **Region switching that nobody notices** — `GET /country?uid=…&country=JP`
  warms up a replacement instance first; the client's connections keep
  flowing while the old instance drains
- 🧾 mihomo subscription endpoint (`/sub?uid=…`) plus plain SOCKS5 for
  anything else
- ⚙️ Full instance lifecycle from the API: register, delete, list servers,
  switch upstream, status
- 🪝 Zero changes to foxyvpn itself — it is only ever started by the wrapper
  (the vendored `1.0.2` package stays byte-identical)

## 🤔 Why wrap foxyvpn?

Plain foxyvpn is a **local** client, by design:

| foxyvpn alone | foxyvpn-pool |
|---|---|
| One SOCKS5 listener, meant for the machine it runs on | Many clients across a trusted network, each with its own exit |
| One process = one client consuming its own token pool | One **shared** token pool, dynamically partitioned into per-instance sets as clients come and go |
| Switching country means restarting the listener — every client connection dies with it | A restart happens **behind** a byte-relay: new connections move to the new instance, existing ones finish on the old one, nobody notices |
| Quota refills are your problem | The wrapper watches the quota, refills token sets ahead of exhaustion, and puts spent accounts back in the pool |

The key trick that makes the invisible switch possible: SOCKS5 carries
exactly **one tunnel per TCP connection**, so the relay in front of each
instance needs to understand no protocol at all — it just moves bytes.
Every client connection is independent; a swap only affects connections that
arrive after it.

## 🧠 How it works

```
client ──socks5h──> <bind-host>:2000x   🚪 front (pure byte relay, no protocol)
                                           │
              old instance keeps serving its connections ◄── 🔁 flip
                                           │                (drain, then retire)
                                   127.0.0.1:300xx    🦊 foxyvpn backend
                                           │
                              *.fastly-masque.net:2499 ──► 🌍 exit
```

Every client (a `uid` of its choosing) gets:

- a **public port** (`20000+`, bound to the network address, stable for its
  lifetime) served by a byte-relay, and
- an **internal** foxyvpn process (`127.0.0.1:30000+`) holding a private
  slice of the token pool (5 pool tokens by default).

Swapping — a new upstream for a country change, or a fresh token set after
quota refills — always follows the same choreography: start and warm up the
replacement → flip the relay → retire the old instance once the connections
it carries have drained.

## ♻️ The shared token pool

- `pool.txt` holds your pre-provisioned FxA session tokens, one per line.
  Each account must already have its Mozilla VPN entitlement activated —
  Guardian refuses (401/403) otherwise.
- Tokens are re-read every poll cycle, so appending to the file is enough —
  no restart needed.
- The wrapper probes Guardian for the remaining quota of every account
  (bounded to 6 concurrent; the access-token exchange is cached in memory)
  and moves an instance to a fresh set **before** its current one runs dry.
  Accounts with quota left return to the pool; empty ones are marked dead.
- If a backend dies on its own (foxyvpn exits when proxy-pass renewal fails
  for 120 s), the next poll cycle replaces it — same public port.

## 🚀 Install

```bash
git clone https://github.com/anton1615/foxyvpn-pool.git ~/foxyvpn-pool
python3 -m venv ~/foxyvpn-pool/.venv
~/foxyvpn-pool/.venv/bin/pip install ~/foxyvpn-pool
```

Configure the token pool and state (kept outside the checkout):

```bash
mkdir -p ~/foxyvpn-data/auth
cp ~/foxyvpn-pool/wrapper/pool.txt.example ~/foxyvpn-data/pool.txt
#   ^ fill pool.txt with your pre-provisioned FxA session tokens
cp ~/foxyvpn-pool/wrapper/auth.example.json ~/foxyvpn-data/auth/user@example.org.json
#   ^ optional: uid/email/quota metadata for nicer logs and a warm quota table
```

A foreground test run:

```bash
~/foxyvpn-pool/.venv/bin/python ~/foxyvpn-pool/wrapper/wrapper.py \
    --pool ~/foxyvpn-data/pool.txt --auth-dir ~/foxyvpn-data/auth \
    --pool-dir ~/foxyvpn-data/pools --db ~/foxyvpn-data/db.sqlite
```

As a systemd --user service:

```bash
cp ~/foxyvpn-pool/wrapper/foxyvpn-pool.service.example \
   ~/.config/systemd/user/foxyvpn-pool.service
systemctl --user daemon-reload && systemctl --user enable --now foxyvpn-pool
journalctl --user -u foxyvpn-pool -f
```

By default the wrapper binds everything to this host's Tailscale address
(and waits for it to appear at boot). Override with `--bind-host`.

## ⚙️ HTTP API

Example host below: `100.100.100.101` — replace with your own.

| Endpoint | Meaning |
|---|---|
| `GET /register?uid=<name>` | 🚪 Reserve a client: allocates tokens, starts its instance, returns its stable port. Idempotent for the same name. Optional `&country=JP` or `&proxy=host:2499` |
| `GET /delete?uid=<name>` | 🗑 Tear the instance down, release tokens and port |
| `GET /sub?uid=<name>` | 🧾 mihomo YAML with that one node |
| `GET /sub` | 🧾 mihomo YAML with every node |
| `GET /list-servers` | 🌍 Country → upstream `host:port` map (public Firefox Remote Settings data) |
| `GET /country?uid=<name>&country=JP` | 🔁 Move the client to another country, invisibly |
| `GET /country?uid=<name>&proxy=host:2499` | 🎯 Pin an exact upstream (mutually exclusive with `country`) |
| `GET /country?uid=<name>` | ↩ Back to the recommended (REC) anycast exit |
| `GET /status` | 📊 Per-client state and pool accounting |

Register a client and use it:

```bash
curl 'http://100.100.100.101:8080/register?uid=laptop'
# → {"uid":"laptop","port":20000,"proxy":"socks5://100.100.100.101:20000",...}
curl --socks5-hostname 100.100.100.101:20000 https://api.ipify.org
```

mihomo (and friends) consume the subscription URL instead:

```
http://100.100.100.101:8080/sub?uid=laptop
```

DNS must resolve on the exit side (`socks5h` semantics): curl uses
`--socks5-hostname`, Firefox sets `network.proxy.socks_remote_dns=true`,
mihomo nodes are plain `socks5` type.

## 🛡️ Security & trust model

**Built for a trusted network — a tailnet, a VPN, or a LAN that you
control.** The SOCKS5 ports and the HTTP API carry **no authentication**,
and the trust boundary is your network's egress, not this service.

Two consequences worth saying out loud:

- 🎯 The intended usage is that every client **only connects to the node it
  created with `/register`** — but nothing enforces that mapping. There is
  no client-to-node protection, so **any client on the network can reach
  any node the host has created**, use its bandwidth quota, or steer it via
  the API with a known `uid`.
- 📡 On a tailnet this is usually acceptable — membership *is* the
  authorization. On an untrusted LAN it is not: do not expose the bind
  address to the public internet.

Backend listeners are loopback-only; the token files and the state DB must
stay `0600`.

## 🧩 Layout

```
foxyvpn/            the foxyvpn 1.0.2 package, vendored from the PyPI wheel
pyproject.toml      build metadata for `pip install .`
wrapper/
  wrapper.py                      the pool wrapper (standalone, stdlib only)
  pool.txt.example                🪙 token pool format
  auth.example.json               optional per-account metadata format
  foxyvpn-pool.service.example   systemd --user unit
```

## 🙏 Credits

- **foxyvpn** Python client — by Vauth, MIT © 2026,
  [PyPI `foxyvpn`](https://pypi.org/project/foxyvpn/). Vendored here
  verbatim from the published `1.0.2` wheel (the project's GitHub host
  currently carries its Android client; the Python source ships as a PyPI
  artifact only).
- foxyvpn describes itself as an independent Python rewrite of
  **[firefox-vpn-client](https://github.com/UjuiUjuMandan/firefox-vpn-client)**
  (Go), whose session-token pool design (`loadSessionTokenPool`,
  `activateNextPoolToken`) this service also leans on.
- The pool wrapper in `wrapper/` is the addition of this repository.
