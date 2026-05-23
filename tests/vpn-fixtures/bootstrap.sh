#!/usr/bin/env bash
# Generates a fresh, throwaway WireGuard keypair and OpenVPN PKI for the integration
# tests in Wormhole.Tests.Integration. All output goes under tests/vpn-fixtures/.out/
# (gitignored). Re-running rotates every secret.
#
# Why generate at runtime instead of committing fixtures: WireGuard private keys are
# curve25519 32-byte values that look identical to real production keys; committing
# them to a public repo creates an auditing footgun even when they're labeled
# "test-only." The PKI directory would also be ~10 files of base64-armored crypto
# material. A 5-second key+PKI generation step is cheaper than the review noise.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$HERE/.out"
WG_OUT="$OUT_DIR/wireguard"
OVPN_OUT="$OUT_DIR/openvpn"

# Match the invoker's uid/gid for files written by docker helper containers
# (kylemanna/openvpn) so subsequent bootstrap re-runs can clean up without
# sudo. CI runners and local devs both get the right ownership.
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

mkdir -p "$WG_OUT" "$OVPN_OUT"

# ---- WireGuard --------------------------------------------------------------
# Prefer the host's wg-tools (CI installs `wireguard-tools` via apt). Fall back
# to running wireguard-tools out of the linuxserver/wireguard image so local
# developers without wg on PATH don't have to install anything system-wide.
#
# IMPORTANT: linuxserver/* images use s6-overlay as their ENTRYPOINT (/init).
# A plain `docker run linuxserver/wireguard wg genkey` would launch the s6
# service tree and IGNORE the CMD — printing nothing to stdout and exiting
# non-zero. Override the entrypoint so the container actually runs `wg`.
gen_wg_key() {
    if command -v wg >/dev/null 2>&1; then
        wg genkey
    else
        docker run --rm --entrypoint wg linuxserver/wireguard:latest genkey
    fi
}
gen_wg_pubkey() {
    # printf '%s\n' (trailing newline) — some wg pubkey implementations require
    # a newline-terminated key on stdin and silently emit an empty key when
    # given a bare 32-byte base64 with no LF. Both branches share the same
    # input shape for consistency.
    if command -v wg >/dev/null 2>&1; then
        printf '%s\n' "$1" | wg pubkey
    else
        printf '%s\n' "$1" | docker run --rm -i --entrypoint wg linuxserver/wireguard:latest pubkey
    fi
}

echo "==> Generating WireGuard keypairs"
SERVER_PRIV="$(gen_wg_key)"
SERVER_PUB="$(gen_wg_pubkey "$SERVER_PRIV")"
CLIENT_PRIV="$(gen_wg_key)"
CLIENT_PUB="$(gen_wg_pubkey "$CLIENT_PRIV")"

# Validate the keys are well-formed before embedding them into configs. A
# silently-empty key (docker stdin race, image-pull glitch under set -e) would
# otherwise produce a malformed wg0.conf that the server accepts but can't
# handshake against — surfacing far downstream as a misleading test timeout.
# WireGuard keys are 44-character base64 with a trailing '='.
for var in SERVER_PRIV SERVER_PUB CLIENT_PRIV CLIENT_PUB; do
    val="${!var}"
    if ! [[ "$val" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        echo "ERROR: $var is malformed (got: '$val'). Check wg / docker keygen output." >&2
        exit 1
    fi
done

echo "==> Writing WireGuard server config ($WG_OUT/wg0.conf)"
# PostUp enables NAT so packets arriving on wg0 from the client (10.13.13.2) can
# reach the docker bridge (10.20.0.0/24) where the echo-target lives. PostDown
# tears down those rules cleanly on container stop / rotation.
cat > "$WG_OUT/wg0.conf" <<EOF
[Interface]
Address = 10.13.13.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV
PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.13.13.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.13.13.0/24 -o eth0 -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.13.13.2/32
EOF

echo "==> Writing WireGuard client config ($WG_OUT/client.json)"
# client.json matches the WireGuardSidecarConfig POCO. The .NET integration test
# deserializes this directly, then hands it to WireGuardProcessHost.StartAsync.
# allowed_ips deliberately narrows the tunnel to the WG + bridge subnets; we do
# NOT route the whole 0.0.0.0/0 because the test process keeps its normal egress.
cat > "$WG_OUT/client.json" <<EOF
{
  "interface_private_key": "$CLIENT_PRIV",
  "interface_address": "10.13.13.2/32",
  "peer_public_key": "$SERVER_PUB",
  "peer_endpoint": "127.0.0.1:51820",
  "allowed_ips": ["10.13.13.0/24", "10.20.0.0/24"],
  "persistent_keepalive_s": 25
}
EOF

# ---- OpenVPN ----------------------------------------------------------------
# kylemanna/openvpn bundles ovpn_genconfig / ovpn_initpki / ovpn_getclient /
# easyrsa. Running them in helper containers against the same volume the runtime
# container will use keeps the PKI layout identical to a production install.

OVPN_IMG="kylemanna/openvpn:latest"

# All helper docker invocations run as the host invoker's uid:gid so the
# generated files (pki/, openvpn.conf, ovpn_env.sh, client.ovpn) are owned by
# the user that ran bootstrap.sh — not container-root, which would block
# re-runs and `git clean` on a local dev box.
DOCKER_USER_ARGS=( --user "$HOST_UID:$HOST_GID" )

# Pre-clean the entire OpenVPN output dir so stale server config / ovpn_env.sh
# from a previous bootstrap don't shadow freshly-rotated PKI. `ovpn_genconfig`
# refuses to overwrite without `-f`, and `ovpn_initpki`'s "Confirm:" prompt is
# not covered by EASYRSA_BATCH. Wiping the dir avoids both. The mkdir below
# recreates it.
#
# Defensive sanity check: if HERE ever resolves badly (script run via
# `bash -c "$(cat bootstrap.sh)"`, broken symlink, refactor that breaks the
# BASH_SOURCE → dirname chain), OVPN_OUT could become an unintended path.
# Require the canonical suffix before the destructive rm.
case "$OVPN_OUT" in
    */tests/vpn-fixtures/.out/openvpn) ;;
    *) echo "ERROR: refusing to rm -rf unexpected OVPN_OUT='$OVPN_OUT'" >&2; exit 1 ;;
esac
rm -rf "$OVPN_OUT"
mkdir -p "$OVPN_OUT"

echo "==> Generating OpenVPN server config (ovpn_genconfig)"
# `-u udp://127.0.0.1:1194` pins the client `remote` to loopback (the server's
# UDP port is published to the host by compose). `-p` pushes a route for the
# docker bridge so the client routes 10.20.0.0/24 through the tunnel and can
# reach the echo-target at 10.20.0.10.
docker run --rm "${DOCKER_USER_ARGS[@]}" -v "$OVPN_OUT:/etc/openvpn" "$OVPN_IMG" \
    ovpn_genconfig -u "udp://127.0.0.1:1194" -p "route 10.20.0.0 255.255.255.0"

echo "==> Initializing OpenVPN PKI (ovpn_initpki nopass)"
# EASYRSA_BATCH + EASYRSA_REQ_CN make initpki non-interactive. `nopass` skips
# the CA passphrase so the server can start unattended.
docker run --rm "${DOCKER_USER_ARGS[@]}" \
    -e EASYRSA_BATCH=1 \
    -e EASYRSA_REQ_CN=Wormhole-Test-CA \
    -v "$OVPN_OUT:/etc/openvpn" "$OVPN_IMG" \
    ovpn_initpki nopass

echo "==> Building OpenVPN client certificate (easyrsa build-client-full client nopass)"
docker run --rm "${DOCKER_USER_ARGS[@]}" \
    -e EASYRSA_BATCH=1 \
    -v "$OVPN_OUT:/etc/openvpn" "$OVPN_IMG" \
    easyrsa build-client-full client nopass

echo "==> Exporting OpenVPN client profile ($OVPN_OUT/client.ovpn)"
# ovpn_getclient inlines the CA / cert / key / tls-auth into the .ovpn blob,
# which is exactly what OpenVpnSidecarConfig.ProfileOvpn expects (the sidecar
# treats the profile as opaque and forwards it to OpenVPN3-core).
#
# Write atomically: a mid-stream failure (e.g. broken pipe) would otherwise
# leave a truncated client.ovpn on disk that the next test run picks up and
# fails to parse with a misleading error.
docker run --rm "${DOCKER_USER_ARGS[@]}" -v "$OVPN_OUT:/etc/openvpn" "$OVPN_IMG" \
    ovpn_getclient client > "$OVPN_OUT/client.ovpn.tmp"
mv "$OVPN_OUT/client.ovpn.tmp" "$OVPN_OUT/client.ovpn"

echo
echo "Bootstrap complete. Now bring up the servers:"
echo "  docker compose -f $HERE/docker-compose.yml up -d --wait"
echo
echo "and export ALL FOUR env vars Wormhole.Tests.Integration expects (proxy"
echo "binaries built per tools/wormhole-{wg,ovpn}proxy/README.md):"
echo "  export WORMHOLE_WGPROXY_PATH=/abs/path/to/wormhole-wgproxy"
echo "  export WORMHOLE_WG_CLIENT_CONFIG=$WG_OUT/client.json"
echo "  export WORMHOLE_OVPNPROXY_PATH=/abs/path/to/wormhole-ovpnproxy"
echo "  export WORMHOLE_OPENVPN_CLIENT_PROFILE=$OVPN_OUT/client.ovpn"
