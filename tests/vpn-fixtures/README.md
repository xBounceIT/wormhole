# VPN test fixtures

Supporting infra for the `Wormhole.Tests.Integration` xUnit project. Stands up a
WireGuard server, an OpenVPN server, a DNS server, and a TCP echo target reachable
only through either tunnel. The integration tests then build a real tunnel handshake
against each server and verify a 4-byte round-trip through the resulting SOCKS5
endpoint — by IP literal, and (for OpenVPN) by a hostname only the in-tunnel
server-pushed DNS can resolve.

## Layout

```
tests/vpn-fixtures/
├── bootstrap.sh           one-shot key + PKI + server/client config generator
├── docker-compose.yml     wireguard + openvpn + echo-target on a shared bridge
└── .out/                  generated, gitignored
    ├── wireguard/
    │   ├── wg0.conf       server config (consumed by linuxserver/wireguard)
    │   └── client.json    WireGuardSidecarConfig JSON for the .NET test
    └── openvpn/
        ├── ovpn_env.sh    server config produced by ovpn_genconfig
        ├── pki/...        CA + server + client certs (kylemanna/openvpn easyrsa)
        └── client.ovpn    inlined .ovpn profile for the .NET test
```

## Why keys aren't committed

`bootstrap.sh` regenerates everything on every run. Real curve25519 / RSA crypto
material in a public repo is an auditing footgun even when labeled "test-only" —
the cost of regenerating is ~5 seconds; the cost of accidentally rotating real
prod keys onto a test fixture path is much higher. The CI job runs the script
inline; local devs run it once before their first `docker compose up`.

## Local usage

```sh
cd tests/vpn-fixtures
./bootstrap.sh                                          # ~5s cached, 30-90s cold (image pulls + RSA CA + cert gen)
HOST_UID=$(id -u) HOST_GID=$(id -g) \
  docker compose up -d --wait --wait-timeout 90         # blocks until healthy
docker compose ps                                       # confirm

# Build the Linux Go sidecars (one-shot)
( cd ../.. && go build -trimpath -o /tmp/wormhole-wgproxy ./tools/wormhole-wgproxy )
# See tools/wormhole-ovpnproxy/README.md for the -tags ovpn3 build.

# Point the integration tests at the running infra
export WORMHOLE_WGPROXY_PATH=/tmp/wormhole-wgproxy
export WORMHOLE_WG_CLIENT_CONFIG=$PWD/.out/wireguard/client.json
export WORMHOLE_OVPNPROXY_PATH=/tmp/wormhole-ovpnproxy
export WORMHOLE_OPENVPN_CLIENT_PROFILE=$PWD/.out/openvpn/client.ovpn

dotnet test ../../Wormhole.Tests.Integration/Wormhole.Tests.Integration.csproj

docker compose down            # tears everything down
```

When the env vars aren't set the tests skip with a reason rather than fail, so the
project is safe to include in default `dotnet test` runs against the solution.

## Network plan

All four containers share the `vpn-test-net` bridge (10.20.0.0/24):

| Container       | Bridge IP   | Tunnel role                            |
| --------------- | ----------- | -------------------------------------- |
| `wireguard`     | 10.20.0.2   | wg0 = 10.13.13.1/24, UDP 51820         |
| `openvpn`       | 10.20.0.3   | tun0 = 10.8.0.1/24, UDP 1194           |
| `echo-target`   | 10.20.0.10  | TCP 7777 (socat echo)                  |
| `dns`           | 10.20.0.53  | dnsmasq: echo.vpn.test → 10.20.0.10    |

Both VPN servers push `10.20.0.0/24` into the tunnel, so when the test's sidecar
dials `10.20.0.10:7777` via SOCKS5, the packet travels through the WireGuard /
OpenVPN data plane to the corresponding server, gets NAT-ed onto the bridge, and
hits the echo target. A successful 4-byte echo proves every layer below the
WinUI 3 surface — Go sidecar, sidecar wire protocol, .NET process host, SOCKS5
client — is working end-to-end.

The OpenVPN server additionally pushes `dhcp-option DNS 10.20.0.53` (bootstrap.sh's
`ovpn_genconfig -n`). The hostname variant of the OpenVPN test dials
`echo.vpn.test:7777` (override: `WORMHOLE_OPENVPN_ECHO_HOSTNAME`) — a name only the
fixture dnsmasq can answer — proving the sidecar plumbs server-pushed DNS into its
gVisor netstack resolver and resolves through the tunnel, never via the OS resolver.
