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
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if __has_include(<openvpn/client/ovpncli.hpp>)
  #define HAVE_OPENVPN3 1
  // Platform/threading defines required before the OpenVPN3 header set.
  // OPENVPN_EXTERNAL_TUN_FACTORY enables the ExternalTun::Factory base class on
  // ClientAPI::OpenVPNClient, which is the entire reason for this rewrite.
  #ifndef OPENVPN_EXTERNAL_TUN_FACTORY
  #define OPENVPN_EXTERNAL_TUN_FACTORY 1
  #endif
  #include <openvpn/log/logbase.hpp>
  #include <openvpn/client/ovpncli.hpp>
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
// Address parsing — minimal push-reply OptionList walker. We only need the
// assigned ifconfig and a couple of metadata fields for the spike.
// ---------------------------------------------------------------------------

// IPv4 dotted-quad netmask → prefix length. -1 on malformed.
static int v4_netmask_to_prefix(const std::string& mask) {
  unsigned a, b, c, d;
  if (std::sscanf(mask.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
  uint32_t m = (a << 24) | (b << 16) | (c << 8) | d;
  // Count leading 1-bits; reject non-contiguous masks.
  int n = 0;
  while (n < 32 && (m & (1u << (31 - n)))) ++n;
  uint32_t check = n == 0 ? 0 : (0xFFFFFFFFu << (32 - n));
  if (check != m) return -1;
  return n;
}

struct PushedAddresses {
  std::string v4_cidr; // "10.8.0.6/24"
  std::string v6_cidr; // "fd00::abc/64"
  int mtu = 1500;
};

static PushedAddresses parse_pushed_addresses(const openvpn::OptionList& opt) {
  PushedAddresses out;

  if (const auto* ifc = opt.get_ptr("ifconfig")) {
    if (ifc->size() >= 3) {
      const auto& addr = ifc->ref(1);
      const auto& mask = ifc->ref(2);
      int prefix = v4_netmask_to_prefix(mask);
      if (prefix >= 0) out.v4_cidr = addr + "/" + std::to_string(prefix);
    }
  }
  if (const auto* ifc6 = opt.get_ptr("ifconfig-ipv6")) {
    if (ifc6->size() >= 2) {
      // ifconfig-ipv6 already arrives as "addr/prefix".
      out.v6_cidr = ifc6->ref(1);
    }
  }
  if (const auto* mtu = opt.get_ptr("tun-mtu")) {
    if (mtu->size() >= 2) {
      try { out.mtu = std::stoi(mtu->ref(1)); } catch (...) {}
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
  int vpn_mtu() const override { return mtu_; }

  // Called by the C ABI ovpn_tun_send (from Go). Schedules the inject onto the
  // io_context thread so parent_.tun_recv() runs in the right context.
  int inject_from_go(const char* buf, int len);

  // Inbound queue — drained by Go via ovpn_tun_recv.
  int dequeue_inbound(char* buf, int buf_len, int timeout_ms);

  // Surface session info to the C ABI; the WormholeClient asks us when
  // wait_connected is invoked. address_cidr is the v4 CIDR if present, else v6.
  std::string assigned_cidr() const {
    if (!ip4_cidr_.empty()) return ip4_cidr_;
    return ip6_cidr_;
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

  std::string ip4_addr_;
  std::string ip4_cidr_;
  std::string ip6_addr_;
  std::string ip6_cidr_;
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
    std::lock_guard<std::mutex> lk(state_m_);
    if (ev.name == "CONNECTED") {
      connected_ = true;
      terminated_ = false;
      last_error_.clear();
    } else if (ev.name == "DISCONNECTED" || ev.fatal) {
      terminated_ = true;
      last_error_ = ev.name + (ev.info.empty() ? "" : ": " + ev.info);
      // Wake any blocked tun_recv waiters; the active TunClient may already be
      // gone by the time event() fires (stop happens before the dtor).
      auto* tc = current_tun_.load(std::memory_order_acquire);
      if (tc) tc->wake_inbound_waiters();
    }
    state_cv_.notify_all();
  }
  void log(const LogInfo& li) override {
    if (log_sink_) log_sink_(li.text);
  }
  void external_pki_cert_request(ExternalPKICertRequest&) override {}
  void external_pki_sign_request(ExternalPKISignRequest&) override {}
  void clock_tick() override {}

  // --- Embedder lifecycle -------------------------------------------------
  int load(const std::string& ovpn) {
    Config cfg;
    cfg.content = ovpn;
    cfg.connTimeout = 30;
    cfg.tunPersist = false; // we own the TUN, not OpenVPN3's persist layer
    cfg.googleDnsFallback = false;
    auto ev = eval_config(cfg);
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
    creds_.replacePasswordWithSessionID = true;
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

  // Extract pushed addresses + MTU from the merged OptionList (profile + push-reply).
  auto pushed = parse_pushed_addresses(opt);
  ip4_cidr_ = pushed.v4_cidr;
  ip6_cidr_ = pushed.v6_cidr;
  mtu_ = pushed.mtu;

  // Bare-address forms used by tun_name/vpn_ip4/vpn_ip6 query methods.
  auto bare = [](const std::string& cidr) -> std::string {
    auto p = cidr.find('/');
    return p == std::string::npos ? cidr : cidr.substr(0, p);
  };
  ip4_addr_ = bare(ip4_cidr_);
  ip6_addr_ = bare(ip6_cidr_);

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
      parent_.tun_recv(outbuf); // encrypt + transport_send
    } catch (const std::exception&) {
      // Drop the packet on any unexpected exception; a future iteration logs.
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
  std::memcpy(buf, pkt.data(), n);
  return n;
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

void ovpn_stop(ovpn_client_t* c) {
#if HAVE_OPENVPN3
  if (!c) return;
  reinterpret_cast<ClientWrapper*>(c)->client->stop_session();
#else
  (void)c;
#endif
}

} // extern "C"
