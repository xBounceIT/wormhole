// shim.h — C ABI exposed by libovpn_shim to the Go side. Wraps OpenVPN3-core's
// openvpn::ClientAPI::OpenVPNClient with a thread-safe TUN packet queue so the parent
// process can drive a userspace TUN through CGO without touching any OS interface.
//
// All functions are thread-safe except where noted. Lifetime: call ovpn_new, then
// ovpn_load_profile / ovpn_set_creds / ovpn_connect_async / ovpn_wait_connected, then
// poll ovpn_tun_recv + ovpn_tun_send until ovpn_stop. Free with ovpn_free.

#ifndef WORMHOLE_OVPN_SHIM_H
#define WORMHOLE_OVPN_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ovpn_client_s ovpn_client_t;

// Create a new client instance. Returns null on allocation failure. Never blocks.
ovpn_client_t* ovpn_new();

// Free a client created by ovpn_new. Safe to call after ovpn_stop. Idempotent on
// already-freed clients (returns immediately).
void ovpn_free(ovpn_client_t* c);

// Load a .ovpn profile blob. Returns 0 on success, non-zero on parse failure. Must be
// called before ovpn_connect_async.
int ovpn_load_profile(ovpn_client_t* c, const char* profile_ovpn);

// Set username/password credentials. Either may be empty/null. Returns 0 on success.
int ovpn_set_creds(ovpn_client_t* c, const char* username, const char* password);

// Provide a response to an OpenVPN dynamic challenge (CRV1). `response` is the user's
// one-time passcode (or "p"/"push" to request an AuthPoint push); `cookie` is the value
// returned by ovpn_get_dynamic_challenge after a prior connect ended in a challenge. Call
// before ovpn_connect_async on a fresh client. OpenVPN3 turns these into the
// CRV1::stateID::response auth string. Returns 0 on success, 100 if built without ovpn3.
int ovpn_set_challenge(ovpn_client_t* c, const char* response, const char* cookie);

// Returns 1 if the most recent ovpn_wait_connected failure was because the server demanded
// a dynamic challenge (rather than a flat auth/transport failure), else 0. Lets the caller
// decide whether retrying with ovpn_set_challenge is worthwhile.
int ovpn_is_dynamic_challenge(ovpn_client_t* c);

// Copy the most recent dynamic-challenge CRV1 cookie into out_buf (NUL-terminated). Returns
// 0 on success, non-zero on bad args, 100 if built without ovpn3.
int ovpn_get_dynamic_challenge(ovpn_client_t* c, char* out_buf, int out_len);

// Kick off the connect on a background thread. Returns 0 if the thread spawned;
// the actual handshake result is reported via ovpn_wait_connected.
int ovpn_connect_async(ovpn_client_t* c);

// Block until the session reaches CONNECTED, fails, or timeout_ms elapses. On success
// writes the assigned interface CIDR (e.g. "10.8.0.6/24") into out_cidr_buf and
// returns 0. On failure returns non-zero; the buffer is left zero-terminated empty.
int ovpn_wait_connected(ovpn_client_t* c, char* out_cidr_buf, int out_cidr_buf_len, int timeout_ms);

// Copy the space-separated list of DNS resolver addresses the server pushed
// ("dhcp-option DNS <ip>" / "dns server <prio> address <ip[:port]> ..." in the
// push-reply) into out_buf (NUL-terminated; empty string when none were pushed).
// Entries may carry a ":port" suffix in the --dns form. Call after
// ovpn_wait_connected succeeds. Returns 0 on success, 1 on bad args, 100 if built
// without OpenVPN3.
int ovpn_get_dns(ovpn_client_t* c, char* out_buf, int out_len);

// Wait up to timeout_ms for the next outbound IP packet from the tunnel (server ->
// client direction in netstack terms) and copy it into buf. Returns the number of
// bytes written, 0 on timeout (caller re-polls), or -1 if the shim is shutting down.
int ovpn_tun_recv(ovpn_client_t* c, char* buf, int buf_len, int timeout_ms);

// Push an inbound IP packet (client -> server direction) into the tunnel. Returns 0
// on success, 1 if the tunnel isn't up yet or is shutting down, 100 if the shim was
// built without OpenVPN3 (HAVE_OPENVPN3=0).
//
// Implementation: the shim uses OPENVPN_EXTERNAL_TUN_FACTORY to install a custom
// TunClient on the OpenVPN3 core. tun_send copies the bytes (Go GC can move the
// slice after this call returns), posts onto the OpenVPN3 io_context thread, and
// calls TunClientParent::tun_recv() — the symmetric outbound path which encrypts
// the packet and hands it to the transport for delivery to the server.
int ovpn_tun_send(ovpn_client_t* c, const char* buf, int buf_len);

// Signal the client to disconnect. Returns immediately; ovpn_tun_recv will start
// returning -1 once the C++ event loop has unwound.
void ovpn_stop(ovpn_client_t* c);

// Copy the last fatal/disconnect reason (e.g. "CONNECTION_TIMEOUT", "AUTH_FAILED: ...",
// "TRANSPORT_ERROR: ...") into out_buf (always NUL-terminated). Returns 0 on success,
// 1 on bad args, 100 if built without OpenVPN3. Empty string when no terminating event
// has fired. Lets the caller report WHY ovpn_wait_connected failed.
int ovpn_last_error(ovpn_client_t* c, char* out_buf, int out_len);

#ifdef __cplusplus
}
#endif

#endif // WORMHOLE_OVPN_SHIM_H
