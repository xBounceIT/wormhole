// shim.cc — OpenVPN3 embedding for libovpn_shim.
//
// Spike implementation using OPENVPN_EXTERNAL_TUN_FACTORY (the documented embedder
// extension point for userspace TUN with bidirectional packet flow):
//
//   - WormholeClient subclasses ClientAPI::OpenVPNClient and overrides
//     ExternalTun::Factory::new_tun_factory() to install our own TunClientFactory.
//   - WormholeTunFactory creates WormholeTunClient instances.
//   - WormholeTunClient implements openvpn::TunClient. The core calls our tun_send()
//     to deliver server→client packets (decrypted IP); we call parent.tun_recv() to
//     inject client→server packets (which the core then encrypts + transmits).
//
// Architecture vs the old TunBuilderBase-style shim:
//   - TunBuilderBase has NO packet-delivery virtual (verified by grep — the old
//     shim's `tun_builder_send` override was a no-op against a non-existent virtual).
//     TunBuilderBase is for configuration callbacks (add address, set MTU) only, and
//     the matching path requires a real OS TUN fd from tun_builder_establish().
//   - ExternalTun::Factory/TunClient is OpenVPN3's first-class embedder hook for the
//     desktop-userspace case where there's no OS TUN. Both directions of packet flow
//     go through documented base classes with virtual destructors.
//
// Threading:
//   - OpenVPN3 runs everything on a single openvpn_io::io_context. All TunClient
//     virtuals are called on that thread.
//   - Go calls ovpn_* from arbitrary goroutines.
//   - For outbound injection (Go → OpenVPN): we copy the bytes immediately (Go GC can
//     move the slice after the C call returns), then openvpn_io::post() onto the
//     io_context so parent_.tun_recv() runs on the correct thread.
//   - For the inbound queue (OpenVPN → Go): a plain mutex + cv. Go's ovpn_tun_recv is
//     a blocking dequeue with timeout, called from a dedicated Go goroutine.

#include "shim.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ovpncli.hpp lives at openvpn3/client/ovpncli.hpp (NOT under openvpn3/openvpn/
// — that's a sibling subtree). The CMakeLists adds `${OPENVPN3_DIR}/client` to
// the include path, so the canonical reference is <client/ovpncli.hpp>. The
// earlier `<openvpn/client/ovpncli.hpp>` form pointed at a non-existent path,
// so __has_include returned false, fell into the else branch, and set
// HAVE_OPENVPN3=0 — which silently disabled the entire real-mode code path
// and made ovpn_new() return nullptr at runtime.
#if __has_include(<client/ovpncli.hpp>)
  #define HAVE_OPENVPN3 1
  // Platform/threading defines required before the OpenVPN3 header set.
  // OPENVPN_EXTERNAL_TUN_FACTORY enables the ExternalTun::Factory base class on
  // ClientAPI::OpenVPNClient, which is the entire reason for this rewrite.
  #ifndef OPENVPN_EXTERNAL_TUN_FACTORY
  #define OPENVPN_EXTERNAL_TUN_FACTORY 1
  #endif
  #include <openvpn/log/logbase.hpp>
  #include <client/ovpncli.hpp>
  #include <openvpn/tun/extern/config.hpp>
  #include <openvpn/tun/extern/fw.hpp>
  #include <openvpn/tun/client/tunbase.hpp>
  #include <openvpn/common/options.hpp>
  #include <openvpn/buffer/buffer.hpp>
  #include <openvpn/frame/frame.hpp>
  #include <openvpn/io/io.hpp>
  using namespace openvpn::ClientAPI;
#else
  #define HAVE_OPENVPN3 0
#endif

namespace {

#if HAVE_OPENVPN3

// Forward declarations so the back-pointer wiring works.
class WormholeClient;
class WormholeTunClient;

// ---------------------------------------------------------------------------
// Address parsing — minimal push-reply OptionList walker. We need the assigned
// addresses, gateway/peer addresses, pushed DNS, and route metadata for the
// userspace sidecar diagnostics.
// ---------------------------------------------------------------------------

static bool parse_v4_dotted_quad(const std::string& value, uint32_t& out) {
  unsigned a, b, c, d;
  char tail;
  if (std::sscanf(value.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4)
    return false;
  if (a > 255 || b > 255 || c > 255 || d > 255) return false;
  out = (a << 24) | (b << 16) | (c << 8) | d;
  return true;
}

// IPv4 dotted-quad netmask → prefix length. -1 on malformed.
static int v4_netmask_to_prefix(const std::string& mask) {
  uint32_t m;
  if (!parse_v4_dotted_quad(mask, m)) return -1;
  // Count leading 1-bits; reject non-contiguous masks.
  int n = 0;
  while (n < 32 && (m & (1u << (31 - n)))) ++n;
  uint32_t check = n == 0 ? 0 : (0xFFFFFFFFu << (32 - n));
  if (check != m) return -1;
  return n;
}

struct PushedAddresses {
  std::string v4_cidr; // "10.8.0.6/24"
  std::string v4_gateway; // "10.8.0.5" for net30/p2p or route-gateway
  std::string v6_cidr; // "fd00::abc/64"
  std::string v6_gateway;
  std::vector<std::string> dns; // pushed resolver addresses, in push order
  std::vector<std::string> routes; // pushed route directives, normalized for logs
  int mtu = 1500;
};

static std::string join_strings(const std::vector<std::string>& values, const char* sep) {
  std::string out;
  for (const auto& v : values) {
    if (!out.empty()) out += sep;
    out += v;
  }
  return out;
}

static PushedAddresses parse_pushed_addresses(const openvpn::OptionList& opt) {
  PushedAddresses out;

  if (const auto* ifc = opt.get_ptr("ifconfig")) {
    if (ifc->size() >= 3) {
      const auto& addr = ifc->ref(1);
      const auto& mask = ifc->ref(2);
      int prefix = v4_netmask_to_prefix(mask);
      if (prefix >= 0) {
        // topology subnet: 2nd field is a dotted-quad netmask.
        out.v4_cidr = addr + "/" + std::to_string(prefix);
      } else {
        // topology net30/p2p (Stormshield's default): the 2nd ifconfig field is the
        // PEER address, not a netmask (e.g. "ifconfig 10.10.135.138 10.10.135.137").
        // Treat the local address as point-to-point (/32). The userspace gVisor
        // netstack routes all traffic out the single TUN via its default route, so the
        // prefix only needs to install the local address. Without this fallback the
        // CIDR is left empty and ovpn_wait_connected spins until its 90s deadline
        // (a long hang) then fails with code 3 even though the tunnel is fully up.
        uint32_t peer;
        out.v4_cidr = addr + "/32";
        if (parse_v4_dotted_quad(mask, peer)) out.v4_gateway = mask;
      }
    }
  }
  if (const auto* rg = opt.get_ptr("route-gateway")) {
    if (rg->size() >= 2) {
      const auto& gw = rg->ref(1);
      uint32_t parsed;
      // Symbolic gateways such as "dhcp" or "vpn_gateway" rely on OpenVPN's
      // adapter routing layer. This sidecar has no OS adapter, so keep the
      // net30/p2p peer fallback unless the server pushed a concrete IPv4 gateway.
      if (parse_v4_dotted_quad(gw, parsed)) out.v4_gateway = gw;
    }
  }
  if (const auto* ifc6 = opt.get_ptr("ifconfig-ipv6")) {
    if (ifc6->size() >= 2) {
      // ifconfig-ipv6 already arrives as "addr/prefix".
      out.v6_cidr = ifc6->ref(1);
    }
    if (ifc6->size() >= 3) {
      out.v6_gateway = ifc6->ref(2);
    }
  }
  if (const auto* mtu = opt.get_ptr("tun-mtu")) {
    if (mtu->size() >= 2) {
      try { out.mtu = std::stoi(mtu->ref(1)); } catch (...) {}
    }
  }

  // Pushed DNS resolvers. Two wire forms can reach the merged OptionList:
  //   dhcp-option DNS <ip>                                  (classic; DNS6 for v6)
  //   dns server <prio> address <ip[:port]> [<ip[:port]>..] (OpenVPN 2.6+ --dns)
  // The Go side feeds these into the netstack so hostname targets resolve through
  // the tunnel; without them every hostname dial fails (the netstack has no OS
  // resolver fallback, by design — it would leak queries outside the tunnel).
  if (const auto* il = opt.get_index_ptr("dhcp-option")) {
    for (auto i : *il) {
      const openvpn::Option& o = opt[i];
      if (o.size() >= 3 && (o.ref(1) == "DNS" || o.ref(1) == "DNS6"))
        out.dns.push_back(o.ref(2));
    }
  }
  if (const auto* il = opt.get_index_ptr("dns")) {
    for (auto i : *il) {
      const openvpn::Option& o = opt[i];
      if (o.size() >= 5 && o.ref(1) == "server" && o.ref(3) == "address") {
        for (std::size_t j = 4; j < o.size(); ++j) out.dns.push_back(o.ref(j));
      }
    }
  }
  if (const auto* il = opt.get_index_ptr("route")) {
    for (auto i : *il) {
      const openvpn::Option& o = opt[i];
      if (o.size() < 2) continue;
      std::string route = o.ref(1);
      if (o.size() >= 3) route += "/" + o.ref(2);
      if (o.size() >= 4) route += " via " + o.ref(3);
      out.routes.push_back(route);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// WormholeTunClient — implements openvpn::TunClient. Single instance per session;
// owned by the OpenVPN3 core via RCPtr<TunClient>.
// ---------------------------------------------------------------------------

class WormholeTunClient : public openvpn::TunClient {
 public:
  WormholeTunClient(openvpn_io::io_context& ioc,
                    openvpn::TunClientParent& parent,
                    openvpn::Frame::Ptr frame,
                    WormholeClient* owner);

  ~WormholeTunClient() override;

  // openvpn::TunClient interface --------------------------------------------
  void tun_start(const openvpn::OptionList& opt,
                 openvpn::TransportClient& transport,
                 openvpn::CryptoDCSettings& dc) override;
  void stop() override;
  void set_disconnect() override;
  bool tun_send(openvpn::BufferAllocated& buf) override; // server → client
  std::string tun_name() const override { return "wormhole-ovpn"; }
  std::string vpn_ip4() const override { return ip4_addr_; }
  std::string vpn_ip6() const override { return ip6_addr_; }
  std::string vpn_gw4() const override { return ip4_gateway_; }
  std::string vpn_gw6() const override { return ip6_gateway_; }
  int vpn_mtu() const override { return mtu_; }

  // Called by the C ABI ovpn_tun_send (from Go). Schedules the inject onto the
  // io_context thread so parent_.tun_recv() runs in the right context.
  int inject_from_go(const char* buf, int len);

  // Inbound queue — drained by Go via ovpn_tun_recv.
  int dequeue_inbound(char* buf, int buf_len, int timeout_ms);

  void set_dial_id(std::uint64_t dial_id);
  std::string stats_string() const;

  // Surface session info to the C ABI; the WormholeClient asks us when
  // wait_connected is invoked. address_cidr is the v4 CIDR if present, else v6.
  // fields_m_ makes the tun_start (io_context thread) → C ABI (Go thread) handoff a
  // proper happens-before: without it the cross-thread read is a data race (the
  // wait_connected polling gate observing a non-empty CIDR does NOT order the other
  // fields — current_tun_ was published back in the constructor).
  std::string assigned_cidr() const {
    std::lock_guard<std::mutex> lk(fields_m_);
    if (!ip4_cidr_.empty()) return ip4_cidr_;
    return ip6_cidr_;
  }

  // Space-separated pushed DNS resolver list ("" when the server pushed none).
  std::string pushed_dns() const {
    std::lock_guard<std::mutex> lk(fields_m_);
    return dns_;
  }

  // Called by stop()/dtor to wake any blocked dequeue_inbound waiters.
  void wake_inbound_waiters() {
    {
      std::lock_guard<std::mutex> lk(inbound_m_);
      shutdown_ = true;
    }
    inbound_cv_.notify_all();
  }

 private:
  openvpn_io::io_context& io_context_;
  openvpn::TunClientParent& parent_;
  openvpn::Frame::Ptr frame_;
  WormholeClient* owner_;

  // Session fields written once by tun_start on the io_context thread and read from
  // the Go thread via assigned_cidr()/pushed_dns(). Guarded by fields_m_ — see the
  // accessor comment for why the wait_connected gate alone is not a handoff.
  mutable std::mutex fields_m_;
  std::string ip4_addr_;
  std::string ip4_cidr_;
  std::string ip4_gateway_;
  std::string ip6_addr_;
  std::string ip6_cidr_;
  std::string ip6_gateway_;
  std::string dns_; // space-separated pushed DNS resolvers
  int mtu_ = 1500;

  // Inbound queue: producer is tun_send on the io_context thread, consumer is
  // dequeue_inbound on a Go-thread (via the C ABI). Buffers are copies because
  // OpenVPN3 reuses BufferAllocated storage after tun_send returns.
  std::mutex inbound_m_;
  std::condition_variable inbound_cv_;
  std::deque<std::vector<char>> inbound_q_;
  bool shutdown_ = false;

  // Stopping flag — set by stop() to suppress further outbound injection.
  std::atomic<bool> stopping_{false};

  std::atomic<std::uint64_t> active_dial_id_{0};
  std::atomic<std::uint64_t> active_dial_log_count_{0};
  std::atomic<std::uint64_t> go_inject_calls_{0};
  std::atomic<std::uint64_t> go_inject_bytes_{0};
  std::atomic<std::uint64_t> core_inject_posts_{0};
  std::atomic<std::uint64_t> core_inject_exceptions_{0};
  std::atomic<std::uint64_t> core_tun_send_packets_{0};
  std::atomic<std::uint64_t> core_tun_send_bytes_{0};
  std::atomic<std::uint64_t> go_dequeue_packets_{0};
  std::atomic<std::uint64_t> go_dequeue_bytes_{0};
  std::atomic<std::uint64_t> go_dequeue_truncations_{0};

  void log_dial_packet_event(const char* event, std::size_t len);
};

// ---------------------------------------------------------------------------
// WormholeTunFactory — produces WormholeTunClient instances. One per session.
// ---------------------------------------------------------------------------

class WormholeTunFactory : public openvpn::TunClientFactory {
 public:
  WormholeTunFactory(openvpn::Frame::Ptr frame, WormholeClient* owner)
      : frame_(std::move(frame)), owner_(owner) {}

  openvpn::TunClient::Ptr new_tun_client_obj(
      openvpn_io::io_context& io_context,
      openvpn::TunClientParent& parent,
      openvpn::TransportClient* /*transport*/) override {
    return openvpn::TunClient::Ptr(new WormholeTunClient(io_context, parent, frame_, owner_));
  }

 private:
  openvpn::Frame::Ptr frame_;
  WormholeClient* owner_;
};

// ---------------------------------------------------------------------------
// WormholeClient — OpenVPNClient subclass. Owns the connect thread, the event
// state machine, and routes the C ABI through to the active TunClient.
// ---------------------------------------------------------------------------

class WormholeClient final : public OpenVPNClient {
 public:
  // Implements ExternalTun::Factory::new_tun_factory (visible because we compile
  // with OPENVPN_EXTERNAL_TUN_FACTORY defined — see ovpncli.hpp ExternalTun::Factory
  // base in the OpenVPNClient bases list).
  openvpn::TunClientFactory* new_tun_factory(
      const openvpn::ExternalTun::Config& conf,
      const openvpn::OptionList& /*opt*/) override {
    // Returned pointer is owned by ClientOptions (it does .reset() into a
    // unique_ptr<TunClientFactory>). Stash a weak observer so we can find the
    // most-recent factory if we ever need to (debug logging, mostly).
    auto* f = new WormholeTunFactory(conf.frame, this);
    last_factory_.store(f, std::memory_order_release);
    return f;
  }

  // --- Event callbacks ----------------------------------------------------
  void event(const Event& ev) override {
    // Mirror EVERY OpenVPN3 connection event to stderr (captured by the parent as
    // "[ovpnproxy] ..." log lines). Without this the parent only ever sees the final
    // "ovpn_wait_connected failed" with no reason — the progression (CONNECTING →
    // WAIT → AUTH → GET_CONFIG, or TRANSPORT_ERROR / AUTH_FAILED / CONNECTION_TIMEOUT)
    // is exactly what's needed to tell a blocked UDP remote apart from a TLS/auth
    // failure. Cheap (one line per state transition) and safe for production.
    std::fprintf(stderr, "[ovpn3-event] %s%s%s%s\n",
                 ev.name.c_str(),
                 ev.error ? " (error)" : "",
                 ev.info.empty() ? "" : ": ",
                 ev.info.c_str());
    std::fflush(stderr);

    std::lock_guard<std::mutex> lk(state_m_);
    if (ev.name == "DYNAMIC_CHALLENGE") {
      // The server wants an OpenVPN data-channel challenge/response (CRV1) — e.g. a
      // WatchGuard AuthPoint 2FA prompt presented at the OpenVPN auth layer, not the web
      // portal. ev.info carries the opaque CRV1 cookie (CRV1:flags:stateID:user:text).
      // Capture it so the caller can retry the connect on a FRESH client with the user's
      // response (set via ovpn_set_challenge -> ProvideCreds.response + dynamicChallengeCookie,
      // which OpenVPN3 turns into the CRV1::stateID::response auth). This event is fatal to the
      // current session, so mark terminated to release wait_connected. NB: keep this branch
      // BEFORE the generic `ev.fatal` branch below, which would otherwise swallow it.
      is_dynamic_challenge_ = true;
      dynamic_challenge_cookie_ = ev.info;
      terminated_ = true;
      last_error_ = "dynamic challenge required";
      auto* tc = current_tun_.load(std::memory_order_acquire);
      if (tc) tc->wake_inbound_waiters();
    } else if (ev.name == "CONNECTED") {
      connected_ = true;
      terminated_ = false;
      last_error_.clear();
      dump_ovpn3_stats("CONNECTED"); // baseline — error counters expected ~zero here
    } else if (ev.name == "DISCONNECTED" || ev.fatal) {
      terminated_ = true;
      last_error_ = ev.name + (ev.info.empty() ? "" : ": " + ev.info);
      // DECISIVE: at KEEPALIVE_TIMEOUT this shows whether server data packets arrived
      // (PACKETS_IN>0) and which crypto layer rejected them (HMAC_ERROR vs DECRYPT_ERROR
      // vs REPLAY_ERROR) — i.e. exactly why the data channel never passed traffic.
      dump_ovpn3_stats(ev.name.c_str());
      // Wake any blocked tun_recv waiters; the active TunClient may already be
      // gone by the time event() fires (stop happens before the dtor).
      auto* tc = current_tun_.load(std::memory_order_acquire);
      if (tc) tc->wake_inbound_waiters();
    }
    state_cv_.notify_all();
  }
  void log(const LogInfo& li) override {
    // Forward OpenVPN3's internal log to stderr too. These lines carry the concrete
    // TLS/transport diagnostics (e.g. mbedTLS "no shared cipher", cert verify errors,
    // "Connecting to [host]:port") that the coarse event() stream doesn't. The parent
    // tags them "[ovpnproxy]"; OpenVPN3 already rate/verbosity-limits its own output.
    std::fprintf(stderr, "[ovpn3] %s", li.text.c_str());
    if (li.text.empty() || li.text.back() != '\n') std::fputc('\n', stderr);
    std::fflush(stderr);
    if (log_sink_) log_sink_(li.text);
  }

  // Snapshot of the last fatal/disconnect reason (e.g. "CONNECTION_TIMEOUT", "AUTH_FAILED:
  // ...", "TRANSPORT_ERROR: ..."). Empty until a terminating event fires. Lets the C ABI
  // surface WHY ovpn_wait_connected failed instead of a bare code.
  std::string last_error() {
    std::lock_guard<std::mutex> lk(state_m_);
    return last_error_;
  }

  // Dump every NON-ZERO OpenVPN3 stat/error counter to stderr (captured by the parent as
  // "[ovpn3-stat] ..." lines). This is the decisive data-channel diagnostic: the per-error
  // counters (HMAC_ERROR / DECRYPT_ERROR / REPLAY_ERROR / BUFFER_ERROR) pinpoint WHY no
  // server data packet ever decrypts — the failure that drives a 10s KEEPALIVE_TIMEOUT
  // (control TLS + auth succeed, then every data packet is dropped). PACKETS_IN vs
  // TUN_PACKETS_IN distinguishes "received but undecryptable" from "never received".
  //   - stats_n()/stats_name() are static; stats_value() is an instance const method that
  //     reads the SAME SessionStats object proto.hpp increments via proto.stats->error(err).
  //   - Safe from event(): foreign-thread stats access is enabled before events dispatch,
  //     and reading the (volatile) counters touches neither state_m_ nor reactor state, and
  //     runs on the same reactor thread that increments them.
  void dump_ovpn3_stats(const char* why) const {
    const int n = OpenVPNClient::stats_n();
    std::fprintf(stderr, "[ovpn3-stat] --- counters at %s ---\n", why);
    for (int i = 0; i < n; ++i) {
      const long long val = this->stats_value(i);
      if (val != 0) {
        const std::string name = OpenVPNClient::stats_name(i);
        std::fprintf(stderr, "[ovpn3-stat] %s=%lld\n", name.c_str(), val);
      }
    }
    std::fprintf(stderr, "[ovpn3-stat] --- end counters ---\n");
    std::fflush(stderr);
  }

  void external_pki_cert_request(ExternalPKICertRequest&) override {}
  void external_pki_sign_request(ExternalPKISignRequest&) override {}
  void clock_tick() override {}

  // The core calls this as a connection nears timeout. Returning false lets it
  // disconnect with a CONNECTION_TIMEOUT event (surfaced to our state machine
  // via event()); we don't want to park the client in an indefinite PAUSE state.
  bool pause_on_connection_timeout() override { return false; }

  // App custom control channel messages are unused by the sidecar — no-op.
  void acc_event(const AppCustomControlMessageEvent&) override {}

  // --- Embedder lifecycle -------------------------------------------------
  int load(const std::string& ovpn) {
    Config cfg;
    cfg.content = ovpn;
    cfg.connTimeout = 30;
    cfg.tunPersist = false; // we own the TUN, not OpenVPN3's persist layer
    cfg.googleDnsFallback = false;
    // Offer non-AEAD data-channel ciphers (e.g. AES-256-CBC) in addition to the modern AEAD
    // suites. OpenVPN core 3.7+ defaults to AEAD-only (AES-GCM / Chacha20-Poly1305) for DCO
    // compatibility, which silently drops a profile's `data-ciphers AES-256-CBC` and makes the
    // data-channel NCP fail with "no shared cipher" against firewalls configured for CBC only
    // (e.g. Stormshield SSL VPN — confirmed live: TLS + auth succeed, then DC negotiation fails).
    // Stock openvpn.exe (the native client) offers CBC, so we match it. CBC+HMAC-SHA256 is still
    // a secure data channel; the VORACLE risk is from compression, which the profile normalizer strips.
    cfg.enableNonPreferredDCAlgorithms = true;
    // Accept pushed compression framing in asymmetric mode: decompress server→client if
    // the server insists, NEVER compress client→server. Legacy OpenVPN 2.x servers very
    // commonly push `comp-lzo no` (stub framing, no actual compression); OpenVPN3's
    // default COMPRESS_NO turns ANY pushed comp option other than stub-v2 into a fatal
    // COMPRESS_ERROR immediately after CONNECTED (cliproto.hpp check_proto_warnings) —
    // confirmed live against the kylemanna fixture server in CI. "asym" matches the
    // official clients; never compressing outbound keeps VORACLE out of scope.
    cfg.compressionMode = "asym";
    auto ev = eval_config(cfg);
    if (!ev.error && ev.externalPki) {
      // The profile carries no inline client cert/key (e.g. Azure P2S Entra ID profiles are
      // auth-user-pass only). OpenVPN3 reads a missing <cert> as "the cert lives in external
      // PKI" and connect() then dies with "Missing External PKI alias" — a dead end here,
      // because this sidecar implements no external PKI (the callbacks above are no-ops).
      // Declare "no client certificate" via the profile directive official cert-less profiles
      // use (OpenVPN Access Server emits it too). NOT Config::disableClientCert: in this
      // OpenVPN3 snapshot that flag only skips the alias check — ClientOptions never wires
      // clientconf.disableClientCert into its legacy disable_client_cert duplicate, so the SSL
      // config still loads with the local cert enabled and fails with "option 'cert' not
      // found". The directive instead clears ParseClientConfig::clientCertEnabled_, which both
      // the alias gate and set_local_cert_enabled consult. A server that genuinely requires a
      // client cert then rejects the TLS handshake with a clear server-side error.
      std::fprintf(stderr, "[ovpn3] profile has no client certificate; connecting with the client-cert path disabled\n");
      std::fflush(stderr);
      cfg.content += "\nsetenv CLIENT_CERT 0\n";
      ev = eval_config(cfg); // re-parse so the directive lands in the state connect() reads
    }
    if (ev.error) {
      last_error_ = ev.message;
      return 1;
    }
    profile_ = std::move(cfg);
    return 0;
  }

  void set_credentials(const std::string& user, const std::string& pass) {
    creds_.username = user;
    creds_.password = pass;
    // Older OpenVPN3 ClientAPI exposed ProvideCreds::replacePasswordWithSessionID
    // to swap the password for the server-issued auth-token (session ID) on
    // renegotiation/reconnect. That field was removed; modern OpenVPN3 does this
    // automatically whenever the server returns an auth-token, so there is nothing
    // to opt into here.
  }

  // Provide a response to an OpenVPN dynamic challenge (CRV1). `cookie` is the value
  // captured from the DYNAMIC_CHALLENGE event (ovpn_get_dynamic_challenge); `response` is
  // the user's one-time passcode, or "p"/"push" to request an AuthPoint push. OpenVPN3
  // combines these into the CRV1::stateID::response auth string on the next connect.
  void set_challenge(const std::string& response, const std::string& cookie) {
    creds_.response = response;
    creds_.dynamicChallengeCookie = cookie;
  }

  // True if the most recent connect() ended because the server demanded a dynamic
  // challenge (rather than a flat auth/transport failure).
  bool is_dynamic_challenge() {
    std::lock_guard<std::mutex> lk(state_m_);
    return is_dynamic_challenge_;
  }

  // The CRV1 cookie from the most recent dynamic challenge (empty if none).
  std::string dynamic_challenge_cookie() {
    std::lock_guard<std::mutex> lk(state_m_);
    return dynamic_challenge_cookie_;
  }

  int connect_async() {
    if (connect_thread_.joinable()) return 1; // already running
    connect_thread_ = std::thread([this]() {
      if (provide_creds(creds_).error) {
        std::lock_guard<std::mutex> lk(state_m_);
        terminated_ = true;
        last_error_ = "provide_creds failed";
        state_cv_.notify_all();
        return;
      }
      auto status = OpenVPNClient::connect();
      std::lock_guard<std::mutex> lk(state_m_);
      terminated_ = true;
      if (status.error) last_error_ = status.message;
      state_cv_.notify_all();
      auto* tc = current_tun_.load(std::memory_order_acquire);
      if (tc) tc->wake_inbound_waiters();
    });
    return 0;
  }

  int wait_connected(char* out_buf, int out_len, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::unique_lock<std::mutex> lk(state_m_);
    state_cv_.wait_until(lk, deadline, [this] {
      return connected_ || terminated_;
    });
    // Order matters: check terminated_ FIRST. A CONNECTED-then-DISCONNECTED race
    // leaves both flags true; if we checked connected_ first we'd return success
    // on a dead session.
    if (terminated_) return 1;
    if (!connected_) return 2; // timeout

    // Pull the assigned address from the active TunClient. CONNECTED signaling
    // and TunClient address population are separate OpenVPN3 callbacks, so under
    // load the TunClient can briefly be empty here even though the session is
    // healthy. Retry against the remaining wait_connected budget so callback
    // ordering doesn't surface as a spurious handshake failure. Release the lock
    // around the sleeps so other state transitions (notably DISCONNECTED) can
    // still acquire it.
    while (true) {
      auto* tc = current_tun_.load(std::memory_order_acquire);
      std::string cidr;
      if (tc) cidr = tc->assigned_cidr();
      if (!cidr.empty()) {
        std::strncpy(out_buf, cidr.c_str(), out_len - 1);
        out_buf[out_len - 1] = '\0';
        return 0;
      }
      if (terminated_) return 1;
      if (std::chrono::steady_clock::now() >= deadline) return 3;
      lk.unlock();
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      lk.lock();
    }
  }

  int tun_recv(char* buf, int buf_len, int timeout_ms) {
    // Locate the active TunClient and dequeue from its inbound queue.
    auto* tc = current_tun_.load(std::memory_order_acquire);
    if (!tc) {
      // No tunnel yet (still connecting) or already torn down. Return 0 on a
      // brief wait so the Go side re-polls; -1 if we're definitely terminated.
      {
        std::lock_guard<std::mutex> lk(state_m_);
        if (terminated_) return -1;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 50)));
      return 0;
    }
    return tc->dequeue_inbound(buf, buf_len, timeout_ms);
  }

  int tun_send(const char* buf, int buf_len) {
    auto* tc = current_tun_.load(std::memory_order_acquire);
    if (!tc) return 1; // tunnel not yet up
    return tc->inject_from_go(buf, buf_len);
  }

  void set_dial_id(std::uint64_t dial_id) {
    auto* tc = current_tun_.load(std::memory_order_acquire);
    if (tc) tc->set_dial_id(dial_id);
  }

  std::string tun_stats() {
    auto* tc = current_tun_.load(std::memory_order_acquire);
    if (!tc) return "active_tun=0";
    return tc->stats_string();
  }

  // Space-separated pushed DNS resolver list ("" when none / tunnel not up).
  std::string pushed_dns() {
    auto* tc = current_tun_.load(std::memory_order_acquire);
    if (!tc) return {};
    return tc->pushed_dns();
  }

  void stop_session() {
    // Idempotent: OpenVPNClient::stop() is conservative about already-stopped
    // state. The atomic guards against double-calls from ovpn_stop + ovpn_free.
    bool expected = false;
    if (stopped_.compare_exchange_strong(expected, true)) {
      OpenVPNClient::stop();
    }
    if (connect_thread_.joinable()) connect_thread_.join();
  }

  // Called by WormholeTunClient ctor/dtor to publish itself for the C ABI.
  void set_current_tun(WormholeTunClient* tc) {
    current_tun_.store(tc, std::memory_order_release);
  }

  using LogSink = void (*)(const std::string&);
  void set_log_sink(LogSink sink) { log_sink_ = sink; }

 private:
  Config profile_;
  ProvideCreds creds_;
  std::thread connect_thread_;
  std::atomic<bool> stopped_{false};

  std::mutex state_m_;
  std::condition_variable state_cv_;
  bool connected_ = false;
  bool terminated_ = false;
  std::string last_error_;
  // Set when a connect ended in an OpenVPN dynamic challenge (CRV1); the cookie is the
  // opaque CRV1:flags:stateID:user:text token to feed back via set_challenge on retry.
  bool is_dynamic_challenge_ = false;
  std::string dynamic_challenge_cookie_;

  std::atomic<WormholeTunClient*> current_tun_{nullptr};
  std::atomic<WormholeTunFactory*> last_factory_{nullptr};

  LogSink log_sink_ = nullptr;
};

// ---------------------------------------------------------------------------
// WormholeTunClient definitions (deferred so they can refer to WormholeClient).
// ---------------------------------------------------------------------------

WormholeTunClient::WormholeTunClient(openvpn_io::io_context& ioc,
                                     openvpn::TunClientParent& parent,
                                     openvpn::Frame::Ptr frame,
                                     WormholeClient* owner)
    : io_context_(ioc), parent_(parent), frame_(std::move(frame)), owner_(owner) {
  if (owner_) owner_->set_current_tun(this);
}

WormholeTunClient::~WormholeTunClient() {
  // Clear the back-pointer FIRST so any in-flight ovpn_tun_send racing with the
  // destructor sees null and bails before dereferencing.
  if (owner_) owner_->set_current_tun(nullptr);
  wake_inbound_waiters();
}

void WormholeTunClient::tun_start(const openvpn::OptionList& opt,
                                  openvpn::TransportClient& /*transport*/,
                                  openvpn::CryptoDCSettings& /*dc*/) {
  parent_.tun_pre_tun_config();

  // Extract pushed addresses + DNS + MTU from the merged OptionList (profile +
  // push-reply). All session fields are stored under fields_m_ so the Go thread's
  // assigned_cidr()/pushed_dns() reads after wait_connected see them coherently.
  auto pushed = parse_pushed_addresses(opt);
  {
    std::lock_guard<std::mutex> lk(fields_m_);
    for (const auto& d : pushed.dns) {
      if (!dns_.empty()) dns_ += ' ';
      dns_ += d;
    }
    ip4_cidr_ = pushed.v4_cidr;
    ip4_gateway_ = pushed.v4_gateway;
    ip6_cidr_ = pushed.v6_cidr;
    ip6_gateway_ = pushed.v6_gateway;
    mtu_ = pushed.mtu;

    // Bare-address forms used by tun_name/vpn_ip4/vpn_ip6 query methods.
    auto bare = [](const std::string& cidr) -> std::string {
      auto p = cidr.find('/');
      return p == std::string::npos ? cidr : cidr.substr(0, p);
    };
    ip4_addr_ = bare(ip4_cidr_);
    ip6_addr_ = bare(ip6_cidr_);
  }

  const auto dns = join_strings(pushed.dns, " ");
  const auto routes = join_strings(pushed.routes, ", ");
  std::fprintf(stderr,
               "openvpn: tunnel config address4=%s gateway4=%s address6=%s gateway6=%s mtu=%d dns=[%s] routes=[%s]\n",
               pushed.v4_cidr.empty() ? "(none)" : pushed.v4_cidr.c_str(),
               pushed.v4_gateway.empty() ? "(none)" : pushed.v4_gateway.c_str(),
               pushed.v6_cidr.empty() ? "(none)" : pushed.v6_cidr.c_str(),
               pushed.v6_gateway.empty() ? "(none)" : pushed.v6_gateway.c_str(),
               pushed.mtu,
               dns.empty() ? "(none)" : dns.c_str(),
               routes.empty() ? "(none)" : routes.c_str());
  std::fflush(stderr);

  parent_.tun_pre_route_config();
  // We don't install routes in the OS — gVisor netstack on the Go side handles
  // all routing inside the process. The core treats this as "routes set up" and
  // proceeds to CONNECTED.
  parent_.tun_connected();
}

void WormholeTunClient::stop() {
  stopping_.store(true, std::memory_order_release);
  wake_inbound_waiters();
}

void WormholeTunClient::set_disconnect() {
  // No special teardown — the io_context shutdown drains pending posts.
}

bool WormholeTunClient::tun_send(openvpn::BufferAllocated& buf) {
  // Server → client direction: OpenVPN3 hands us a decrypted IP packet to deliver
  // to the (virtual) TUN. Copy into the inbound queue for the Go side to drain
  // via ovpn_tun_recv.
  if (stopping_.load(std::memory_order_acquire)) return false;
  const char* data = reinterpret_cast<const char*>(buf.c_data());
  const std::size_t len = buf.size();
  if (len == 0) return true;
  core_tun_send_packets_.fetch_add(1, std::memory_order_relaxed);
  core_tun_send_bytes_.fetch_add(static_cast<std::uint64_t>(len), std::memory_order_relaxed);
  log_dial_packet_event("core_tun_send", len);
  {
    std::lock_guard<std::mutex> lk(inbound_m_);
    inbound_q_.emplace_back(data, data + len);
  }
  inbound_cv_.notify_one();
  return true;
}

int WormholeTunClient::inject_from_go(const char* buf, int len) {
  if (len <= 0 || !buf) return 1;
  if (stopping_.load(std::memory_order_acquire)) return 1;
  go_inject_calls_.fetch_add(1, std::memory_order_relaxed);
  go_inject_bytes_.fetch_add(static_cast<std::uint64_t>(len), std::memory_order_relaxed);
  log_dial_packet_event("go_inject_from_go", static_cast<std::size_t>(len));

  // Critical: copy NOW. The Go runtime pins the pointer only for the duration of
  // the C call. Once we return from ovpn_tun_send, the next dev.Read on the Go
  // side reuses the slice and overwrites buf's backing array — but our io_context
  // post may still be queued.
  std::vector<uint8_t> pkt(reinterpret_cast<const uint8_t*>(buf),
                           reinterpret_cast<const uint8_t*>(buf) + len);

  // Capture-by-move into the post so the bytes live for the lifetime of the
  // queued lambda. Frame::prepare gives us the correct headroom for the encrypt
  // path (READ_TUN context — "data read from TUN, about to be encrypted").
  openvpn::Frame::Ptr frame = frame_;
  openvpn_io::post(io_context_, [this, frame, pkt = std::move(pkt)]() {
    if (stopping_.load(std::memory_order_acquire)) return;
    try {
      openvpn::BufferAllocated outbuf;
      frame->prepare(openvpn::Frame::READ_TUN, outbuf);
      outbuf.write(pkt.data(), pkt.size());
      core_inject_posts_.fetch_add(1, std::memory_order_relaxed);
      log_dial_packet_event("core_tun_recv_post", pkt.size());
      parent_.tun_recv(outbuf); // encrypt + transport_send
    } catch (const std::exception&) {
      core_inject_exceptions_.fetch_add(1, std::memory_order_relaxed);
      log_dial_packet_event("core_tun_recv_exception", pkt.size());
    }
  });
  return 0;
}

int WormholeTunClient::dequeue_inbound(char* buf, int buf_len, int timeout_ms) {
  std::unique_lock<std::mutex> lk(inbound_m_);
  if (!inbound_cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms), [this] {
        return !inbound_q_.empty() || shutdown_;
      })) {
    return 0; // timeout
  }
  if (inbound_q_.empty()) return shutdown_ ? -1 : 0;
  auto pkt = std::move(inbound_q_.front());
  inbound_q_.pop_front();
  int n = std::min<int>(static_cast<int>(pkt.size()), buf_len);
  if (n < static_cast<int>(pkt.size())) {
    go_dequeue_truncations_.fetch_add(1, std::memory_order_relaxed);
  }
  std::memcpy(buf, pkt.data(), n);
  go_dequeue_packets_.fetch_add(1, std::memory_order_relaxed);
  go_dequeue_bytes_.fetch_add(static_cast<std::uint64_t>(n), std::memory_order_relaxed);
  log_dial_packet_event("go_ovpn_tun_recv_dequeue", static_cast<std::size_t>(n));
  return n;
}

void WormholeTunClient::set_dial_id(std::uint64_t dial_id) {
  active_dial_id_.store(dial_id, std::memory_order_release);
  active_dial_log_count_.store(0, std::memory_order_release);
  if (dial_id != 0) {
    std::fprintf(stderr, "[ovpn3-tun] dial_id=%llu active\n",
                 static_cast<unsigned long long>(dial_id));
    std::fflush(stderr);
  }
}

std::string WormholeTunClient::stats_string() const {
  char buf[512];
  std::snprintf(
      buf,
      sizeof(buf),
      "active_tun=1 go_inject_calls=%llu go_inject_bytes=%llu core_inject_posts=%llu core_inject_exceptions=%llu core_tun_send_packets=%llu core_tun_send_bytes=%llu go_dequeue_packets=%llu go_dequeue_bytes=%llu go_dequeue_truncations=%llu",
      static_cast<unsigned long long>(go_inject_calls_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(go_inject_bytes_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(core_inject_posts_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(core_inject_exceptions_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(core_tun_send_packets_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(core_tun_send_bytes_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(go_dequeue_packets_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(go_dequeue_bytes_.load(std::memory_order_relaxed)),
      static_cast<unsigned long long>(go_dequeue_truncations_.load(std::memory_order_relaxed)));
  return std::string(buf);
}

void WormholeTunClient::log_dial_packet_event(const char* event, std::size_t len) {
  const std::uint64_t dial_id = active_dial_id_.load(std::memory_order_acquire);
  if (dial_id == 0) return;
  const std::uint64_t n = active_dial_log_count_.fetch_add(1, std::memory_order_acq_rel);
  if (n >= 32) return;
  std::fprintf(stderr, "[ovpn3-tun] dial_id=%llu event=%s len=%llu\n",
               static_cast<unsigned long long>(dial_id),
               event,
               static_cast<unsigned long long>(len));
  std::fflush(stderr);
}

#endif // HAVE_OPENVPN3

// ---------------------------------------------------------------------------
// Wrapper for the C ABI: stable across HAVE_OPENVPN3 states.
// ---------------------------------------------------------------------------
struct ClientWrapper {
#if HAVE_OPENVPN3
  std::unique_ptr<WormholeClient> client;
#endif
  std::atomic<bool> freed{false};
};

} // namespace

extern "C" {

ovpn_client_t* ovpn_new() {
#if HAVE_OPENVPN3
  auto* w = new ClientWrapper();
  w->client = std::make_unique<WormholeClient>();
  return reinterpret_cast<ovpn_client_t*>(w);
#else
  return nullptr;
#endif
}

void ovpn_free(ovpn_client_t* c) {
#if HAVE_OPENVPN3
  if (!c) return;
  auto* w = reinterpret_cast<ClientWrapper*>(c);
  if (w->freed.exchange(true)) return;
  if (w->client) w->client->stop_session();
  delete w;
#else
  (void)c;
#endif
}

int ovpn_load_profile(ovpn_client_t* c, const char* profile_ovpn) {
#if HAVE_OPENVPN3
  if (!c || !profile_ovpn) return 1;
  return reinterpret_cast<ClientWrapper*>(c)->client->load(profile_ovpn);
#else
  (void)c; (void)profile_ovpn;
  return 100;
#endif
}

int ovpn_set_creds(ovpn_client_t* c, const char* username, const char* password) {
#if HAVE_OPENVPN3
  if (!c) return 1;
  reinterpret_cast<ClientWrapper*>(c)->client->set_credentials(
      username ? username : "", password ? password : "");
  return 0;
#else
  (void)c; (void)username; (void)password;
  return 100;
#endif
}

int ovpn_connect_async(ovpn_client_t* c) {
#if HAVE_OPENVPN3
  if (!c) return 1;
  return reinterpret_cast<ClientWrapper*>(c)->client->connect_async();
#else
  (void)c;
  return 100;
#endif
}

int ovpn_wait_connected(ovpn_client_t* c, char* out_cidr_buf, int out_cidr_buf_len, int timeout_ms) {
#if HAVE_OPENVPN3
  if (!c || !out_cidr_buf || out_cidr_buf_len < 1) return 1;
  return reinterpret_cast<ClientWrapper*>(c)->client->wait_connected(out_cidr_buf, out_cidr_buf_len, timeout_ms);
#else
  (void)c; (void)out_cidr_buf; (void)out_cidr_buf_len; (void)timeout_ms;
  return 100;
#endif
}

int ovpn_get_dns(ovpn_client_t* c, char* out_buf, int out_len) {
#if HAVE_OPENVPN3
  if (!c || !out_buf || out_len < 1) return 1;
  const std::string dns = reinterpret_cast<ClientWrapper*>(c)->client->pushed_dns();
  std::strncpy(out_buf, dns.c_str(), out_len - 1);
  out_buf[out_len - 1] = '\0';
  return 0;
#else
  (void)c; (void)out_buf; (void)out_len;
  return 100;
#endif
}

int ovpn_tun_recv(ovpn_client_t* c, char* buf, int buf_len, int timeout_ms) {
#if HAVE_OPENVPN3
  if (!c || !buf || buf_len < 1) return -1;
  return reinterpret_cast<ClientWrapper*>(c)->client->tun_recv(buf, buf_len, timeout_ms);
#else
  (void)c; (void)buf; (void)buf_len; (void)timeout_ms;
  return -1;
#endif
}

int ovpn_tun_send(ovpn_client_t* c, const char* buf, int buf_len) {
#if HAVE_OPENVPN3
  if (!c) return 1;
  return reinterpret_cast<ClientWrapper*>(c)->client->tun_send(buf, buf_len);
#else
  (void)c; (void)buf; (void)buf_len;
  return 100;
#endif
}

void ovpn_set_dial_id(ovpn_client_t* c, unsigned long long dial_id) {
#if HAVE_OPENVPN3
  if (!c) return;
  reinterpret_cast<ClientWrapper*>(c)->client->set_dial_id(static_cast<std::uint64_t>(dial_id));
#else
  (void)c; (void)dial_id;
#endif
}

int ovpn_tun_stats(ovpn_client_t* c, char* out_buf, int out_len) {
#if HAVE_OPENVPN3
  if (!c || !out_buf || out_len < 1) return 1;
  const std::string stats = reinterpret_cast<ClientWrapper*>(c)->client->tun_stats();
  std::strncpy(out_buf, stats.c_str(), out_len - 1);
  out_buf[out_len - 1] = '\0';
  return 0;
#else
  (void)c; (void)out_buf; (void)out_len;
  return 100;
#endif
}

void ovpn_stop(ovpn_client_t* c) {
#if HAVE_OPENVPN3
  if (!c) return;
  reinterpret_cast<ClientWrapper*>(c)->client->stop_session();
#else
  (void)c;
#endif
}

int ovpn_last_error(ovpn_client_t* c, char* out_buf, int out_len) {
#if HAVE_OPENVPN3
  if (!c || !out_buf || out_len < 1) return 1;
  const std::string err = reinterpret_cast<ClientWrapper*>(c)->client->last_error();
  std::strncpy(out_buf, err.c_str(), out_len - 1);
  out_buf[out_len - 1] = '\0';
  return 0;
#else
  (void)c; (void)out_buf; (void)out_len;
  return 100;
#endif
}

int ovpn_set_challenge(ovpn_client_t* c, const char* response, const char* cookie) {
#if HAVE_OPENVPN3
  if (!c) return 1;
  reinterpret_cast<ClientWrapper*>(c)->client->set_challenge(
      response ? response : "", cookie ? cookie : "");
  return 0;
#else
  (void)c; (void)response; (void)cookie;
  return 100;
#endif
}

int ovpn_is_dynamic_challenge(ovpn_client_t* c) {
#if HAVE_OPENVPN3
  if (!c) return 0;
  return reinterpret_cast<ClientWrapper*>(c)->client->is_dynamic_challenge() ? 1 : 0;
#else
  (void)c;
  return 0;
#endif
}

int ovpn_get_dynamic_challenge(ovpn_client_t* c, char* out_buf, int out_len) {
#if HAVE_OPENVPN3
  if (!c || !out_buf || out_len < 1) return 1;
  const std::string cookie = reinterpret_cast<ClientWrapper*>(c)->client->dynamic_challenge_cookie();
  std::strncpy(out_buf, cookie.c_str(), out_len - 1);
  out_buf[out_len - 1] = '\0';
  return 0;
#else
  (void)c; (void)out_buf; (void)out_len;
  return 100;
#endif
}

} // extern "C"
