# foxyvpn-pool

**Per-client Mozilla VPN SOCKS5 exits on top of the `foxyvpn` Python
client** (vendored in this repository): a small service that gives each of
your clients its own dedicated exit behind a stable port, driven by an HTTP
API and a mihomo-compatible subscription endpoint.

`foxyvpn` is the Local SOCKS5 proxy client for the Mozilla VPN / Firefox VPN
proxy service, published on [PyPI](https://pypi.org/project/foxyvpn/) by
Vauth (MIT). This repository vendors its `1.0.2` release unchanged and adds
the pool wrapper; see [Credits](#credits) for the full lineage.

> Unofficial community software. Not affiliated with or endorsed by Mozilla.
> Only use it with accounts and a subscription you are authorized to use, in
> accordance with Mozilla's terms of service.

## What the wrapper does

`wrapper/wrapper.py` hands out **one dedicated Mozilla VPN exit per client**.
A client asks for a node with a name of its own choosing, the wrapper starts
a `foxyvpn` instance for it, and the client keeps a stable SOCKS5 port for as
long as it wants.

```
client ──socks5h──> <bind-host>:2000x   front (pure byte relay, no protocol)
                                           │
              old instance keeps serving its connections ◄── flip
                                           │                (drain, then retire)
                                   127.0.0.1:300xx    foxyvpn backend
                                           │
                              *.fastly-masque.net:2499 ──► exit
```

Because SOCKS5 carries one tunnel per TCP connection, the relay needs to know
no protocol at all, and **switching a client to a replacement instance is
invisible**: the replacement is started and warmed up first, the relay is
pointed at it, and the previous instance is retired only after the connections
it already carries have drained.

Per client the wrapper assigns **5 pool tokens** (configurable in the source)
and moves it to a fresh set — again invisibly — once even the healthiest
token in its set drops below 5% of the monthly quota. Quota figures come from
the `X-Quota-*` headers of Guardian's proxy-pass responses; the pool is
re-read every poll cycle, so tokens appended to `pool.txt` later are picked
up automatically.

## Install

```bash
git clone https://github.com/anton1615/foxyvpn-pool.git ~/foxyvpn-pool
python3 -m venv ~/foxyvpn-pool/.venv
~/foxyvpn-pool/.venv/bin/pip install ~/foxyvpn-pool
```

State (kept outside the checkout):

```bash
mkdir -p ~/foxyvpn-data/auth
cp ~/foxyvpn-pool/wrapper/pool.txt.example ~/foxyvpn-data/pool.txt
#   ^ fill pool.txt with your pre-provisioned FxA session tokens.
#     Every account must already have its Mozilla VPN entitlement
#     activated -- Guardian refuses (401/403) otherwise.
cp ~/foxyvpn-pool/wrapper/auth.example.json ~/foxyvpn-data/auth/user@example.org.json
#   ^ optional: uid/email/quota metadata for nicer logs and a warm quota table
```

Foreground test run:

```bash
~/foxyvpn-pool/.venv/bin/python ~/foxyvpn-pool/wrapper/wrapper.py \
    --pool ~/foxyvpn-data/pool.txt --auth-dir ~/foxyvpn-data/auth \
    --pool-dir ~/foxyvpn-data/pools --db ~/foxyvpn-data/db.sqlite
```

As a service (systemd --user):

```bash
cp ~/foxyvpn-pool/wrapper/foxyvpn-pool.service.example \
   ~/.config/systemd/user/foxyvpn-pool.service
systemctl --user daemon-reload && systemctl --user enable --now foxyvpn-pool
journalctl --user -u foxyvpn-pool -f
```

By default the wrapper binds everything to this host's Tailscale address
(and waits for it to appear at boot). Override with `--bind-host`.

## API

Example host below: `100.100.100.101` — replace with your own.

| Endpoint | Meaning |
|---|---|
| `GET /register?uid=<name>` | Reserve a client: allocates tokens, starts an instance, returns its stable port. Idempotent for the same name. Optional `&country=JP` or `&proxy=host:2499` |
| `GET /delete?uid=<name>` | Tear the instance down, release tokens and port |
| `GET /sub?uid=<name>` | mihomo YAML with that one node |
| `GET /sub` | mihomo YAML with every node |
| `GET /list-servers` | Country → upstream `host:port` map (public Firefox Remote Settings data) |
| `GET /country?uid=<name>&country=JP` | Move the client to another country (invisible to it) |
| `GET /country?uid=<name>&proxy=host:2499` | Pin an exact upstream (`--proxy`, mutually exclusive with country) |
| `GET /country?uid=<name>` | Back to the recommended (REC) anycast exit |
| `GET /status` | Per-client state and pool accounting |

Register and use:

```bash
curl 'http://100.100.100.101:8080/register?uid=laptop'
# → {"uid":"laptop","port":20000,"proxy":"socks5://100.100.100.101:20000",...}
curl --socks5-hostname 100.100.100.101:20000 https://api.ipify.org
```

mihomo subscribers use the subscription URL instead:

```
http://100.100.100.101:8080/sub?uid=laptop
```

DNS must resolve on the exit side (`socks5h` semantics): curl uses
`--socks5-hostname`, Firefox sets `network.proxy.socks_remote_dns=true`,
mihomo nodes are plain `socks5` type.

## Internal design notes

- Public ports come from a monotonic counter persisted in `db.sqlite`, so a
  subscription never goes stale; internal foxyvpn ports (loopback only) come
  from a second counter.
- foxyvpn is only ever **started**, never modified: the single argv assembly
  point is `spawn_backend()`, and the control plane simply imports the
  package's own modules (`foxyvpn.fxa`, `foxyvpn.guardian`,
  `foxyvpn.serverlist`).
- A backend that dies on its own (`foxyvpn` exits when proxy-pass renewal
  fails for 120 s) is replaced on the next poll cycle with the same public
  port.
- On startup the wrapper kills sessions it started earlier, re-listens on
  every recorded public port, and re-launches each instance from the DB.
- Quota probes are bounded (6 concurrent) and remember each account's
  access token in memory; Guardian has no observed rate limit but a shared
  HTTP client chokes under a big burst.

## Security

The SOCKS5 ports and the API carry **no authentication** — the wrapper is
built for a private network (a tailnet, a VPN, or a LAN you trust). Do not
expose the bind address to the public internet; egress filtering at the
network layer is the intended trust boundary. The backend listeners are
loopback-only; the token files and state DB must stay `0600`.

## Layout

```
foxyvpn/            the foxyvpn 1.0.2 package, vendored from the PyPI wheel
pyproject.toml      build metadata for `pip install .`
wrapper/
  wrapper.py                 the pool wrapper (standalone, stdlib only)
  pool.txt.example           token pool format
  auth.example.json          optional per-account metadata format
  foxyvpn-pool.service.example   systemd --user unit
```

## Credits

- **foxyvpn** Python client — by Vauth, MIT © 2026, [PyPI
  `foxyvpn`](https://pypi.org/project/foxyvpn/). Vendored here verbatim from
  the published `1.0.2` wheel (the project's GitHub host currently carries
  its Android client; the Python source ships as a PyPI artifact only).
- foxyvpn describes itself as an independent Python rewrite of
  **[firefox-vpn-client](https://github.com/UjuiUjuMandan/firefox-vpn-client)**
  (Go), whose session-token pool design (`loadSessionTokenPool`,
  `activateNextPoolToken`) this service also leans on.
- The pool wrapper in `wrapper/` is the addition of this repository.
