/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "http.h"

#include <chrono>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>
#include <openssl/ssl.h>
#include <random>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/MemArena.h"
#include "swoc/swoc_ip.h"
#include "swoc/TextView.h"

class HttpHeader;
struct Txn;

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
namespace bwf
{
/** Format wrapper for @c ngtcp2 errors.
 */
struct Ngtcp2Error
{
  int _e;
  explicit Ngtcp2Error(int e) : _e(e) { }
};

/** Format wrapper for @c nghttp3 errors.
 */
struct Nghttp3Error
{
  int _e;
  explicit Nghttp3Error(int e) : _e(e) { }
};
} // namespace bwf

BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::Ngtcp2Error const &error);
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, bwf::Nghttp3Error const &error);
} // namespace SWOC_VERSION_NS
} // namespace swoc

/** Encapsulate the buffer for the QUIC hanshake. */
class QuicHandshake
{
public:
  QuicHandshake();
  ~QuicHandshake() = default;

  QuicHandshake(QuicHandshake const &) = delete;
  QuicHandshake &operator=(QuicHandshake const &) = delete;

public:
  /** This is the maximum number of bytes we expect to use for the QUIC
   * handshake.
   *
   * This max value is taken from CURL code which has a comment expressing
   * tentative hope that this should be large enough. There is an assertion in
   * our (and theirs, I believe) implementation guarding this invariant. If we
   * trip that, we may need to expand this.
   */
  static constexpr size_t max_handshake_size = 4 * 1024;

  /** This contains the storage for the QUIC handshake. */
  std::vector<char> buf;
};

/** The various elements related to the ngtcp2 API calls.
 *
 * For reference, this is based off of curl's struct quicsocket in ngtcp2.h.
 */
class QuicSocket
{
public:
  QuicSocket();
  ~QuicSocket();
  QuicSocket(QuicSocket const &) = delete;
  QuicSocket &operator=(QuicSocket const &) = delete;

  /** Open a QUIC log file for writing.
   *
   * This assumes that scid has been previously configured.
   */
  swoc::Errata open_qlog_file();

  /** Randomly populate an array of a given size.
   *
   * This is used to initialize the various connection ids.
   *
   * @param[in] array The buffer to populate
   *
   * @param[in] array_len The number of bytes in the array to populate.
   */
  static void randomly_populate_array(uint8_t *array, size_t array_len);

  /** Configure QUIC logging for the provided directory.
   *
   * @param[in] qlog_dir The directory into which QUIC log files should be
   * written.
   */
  static swoc::Errata configure_qlog_dir(swoc::TextView qlog_dir);

  /** The callback function for ngtcp2 QUIC logging.
   *
   * For details, see the ngtcp2 document for ngtcp2_qlog_write.
   */
  static void qlog_callback(void *user_data, uint32_t flags, const void *data, size_t datalen);

public:
  ngtcp2_conn *qconn = nullptr;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  uint32_t version = 0;
  ngtcp2_settings settings;
  ngtcp2_transport_params transport_params;
  SSL_CTX *sslctx = nullptr;
  SSL *ssl = nullptr;
  /// 3 is the maximum enum value in ngtcp2_crypto_level.
  static constexpr int MAX_NGTCP2_CRYPTO_LEVEL = 3;
  // The indexing starts with 0, thus if the MAX_NGTCP2_CRYPTO_LEVEL is 3,
  // there can be 4 entries (0 to 3, inclusive).
  QuicHandshake crypto_data[MAX_NGTCP2_CRYPTO_LEVEL + 1];
  /* The last TLS alert description generated by the local endpoint */
  uint8_t tls_alert = 0;
  swoc::IPEndpoint local_addr;

  nghttp3_conn *h3conn = nullptr;
  nghttp3_settings h3settings;
  int qlogfd = -1;

private:
  // Members to support random number generation for connection id.
  static std::random_device _rd;
  static std::mt19937 _rng;
  static std::uniform_int_distribution<int> _uni_id;

  /** The directory into which QUIC log files will be written.
   *
   * This may be empty. If so, no QUIC logging will take place.
   */
  static swoc::file::path _qlog_dir;

  /// A mutex to ensure serialized writing to qlogfd.
  static std::mutex _qlog_mutex;
};

/** Representation of an HTTP/3 stream (a single transaction). */
class H3StreamState
{
public:
  /**
   * @param[in] is_client Whether this stream state is for a client. That is,
   * is this stream state functioning as a client that will send a request, or
   * a server receiving a request and sending a response.
   */
  H3StreamState(bool is_client);
  ~H3StreamState();

  /// Whether this stream is for a server receiving a request from a client.
  bool will_receive_request() const;

  /// Whether this stream is for a client receiving a response from a server.
  bool will_receive_response() const;

  /// Set the stream_id for this and the appropriate members.
  void set_stream_id(int64_t stream_id);

  /// Retrieve the stream id for this stream.
  int64_t get_stream_id() const;

  /** Increment the nghttp3 reference count on buf and return a view of it.
   *
   * A reference count to the buffer will be held for the remainder of the
   * lifetime of the stream.
   *
   * @param[in] buf The nghttp3 ref counted buffer to register and for which a
   * TextView will be returned.
   *
   * @return A view representation of the given buffer.
   */
  swoc::TextView register_rcbuf(nghttp3_rcbuf *rcbuf);

public:
  /// The key identifying this HTTP transaction.
  std::string key;

  /** The composed URL parts from :method, :authority, and :path pseudo headers
   * from the request.
   *
   * This is stored in this object to persist its storage because parse_url
   * assigns from this string TextViews.
   */
  std::string composed_url;

  /// Headers have been received from the peer.
  bool have_received_headers = false;

  /// The time the stream started. Used for timing calculations.
  std::chrono::time_point<std::chrono::system_clock> stream_start;

  /// The HTTP request headers for this stream.
  std::shared_ptr<HttpHeader> request_from_client;

  /// The HTTP response headers for this stream.
  std::shared_ptr<HttpHeader> response_from_server;

  /// The request the YAML file indicated should be received from the client.
  //
  // This is only used when will_receive_request is True
  HttpHeader const *specified_request = nullptr;

  /// The response the YAML file indicated should be received from the server.
  //
  // This is only used when will_receive_response is True.
  HttpHeader const *specified_response = nullptr;

  /// The body received.
  std::string body_received;

  /// The body that will be sent for this message.
  swoc::TextView body_to_send;

  /** For requests, whether this requests is waiting for a 100 Continue
   * response. */
  bool wait_for_continue = false;

  /// The number unacknowledged data frame bytes sent.
  size_t num_data_bytes_written = 0;

private:
  /// Whether this H3StreamState will be receiving a request (i.e., is an
  /// H3StreamState for a server).
  bool _will_receive_request = false;

  /** The QUIC stream ID for this stream. */
  int64_t _stream_id = 0;
  std::deque<nghttp3_rcbuf *> _rcbufs_to_free;
};

/** Representation of an HTTP/3 connection.
 *
 * An H3Session has a one to many relationship with H3StreamState objects.
 */
class H3Session : public Session
{
public:
  using super_type = Session;
  H3Session();
  H3Session(swoc::TextView const &client_sni, int client_verify_mode = SSL_VERIFY_NONE);
  ~H3Session();
  swoc::Rv<ssize_t> read(swoc::MemSpan<char> span) override;
  swoc::Rv<ssize_t> write(swoc::TextView data) override;
  swoc::Rv<ssize_t> write(HttpHeader const &hdr) override;

  /** Populate an nghttp3_nv header vector structure from an HttpHeader. */
  swoc::Errata pack_headers(HttpHeader const &hdr, nghttp3_nv *&nv_hdr, int &hdr_count);

  /** For HTTP/3, we read on the socket until an entire stream is done.
   *
   * For HTTP/1, we first read headers to get the Content-Length or other
   * header information to direct reading the body. For HTTP/3, this isn't
   * an issue because bodies are explicitly framed.
   */
  swoc::Rv<int> poll_for_headers(std::chrono::milliseconds timeout) override;
  swoc::Rv<std::shared_ptr<HttpHeader>> read_and_parse_request(swoc::FixedBufferWriter &w) override;
  swoc::Rv<size_t> drain_body(
      HttpHeader const &hdr,
      size_t expected_content_size,
      swoc::TextView bytes_read,
      std::shared_ptr<RuleCheck> rule_check = nullptr) override;

  /** Perform the server-side QUIC handshake for a connection. */
  swoc::Errata accept() override;

  /** Perform the client-side QUIC handshake for a connection. */
  swoc::Errata connect() override;

  /** Establish a QUIC connection from the given interface to the given IP
   * address. */
  swoc::Errata do_connect(
      swoc::TextView interface,
      swoc::IPEndpoint const *target,
      ProxyProtocolVersion pp_version = ProxyProtocolVersion::NONE) override;

  /** Perform HTTP/3 global initialization.
   *
   * @param[in] process_exit_code: The integer to set to non-zero on failure
   * conditions. This is necessary because many ngtcp2 and nghttp3 callbacks do
   * not have direct returns to their callers.
   *
   * @param[in] qlog_dir The directory for qlog files. If this is an empty
   * string, no QUIC logging will be done.
   */
  static swoc::Errata init(int *process_exit_code, swoc::TextView qlog_dir);

  /** Delete global instances. */
  static void terminate();

  /** Indicates that that the user should receive a non-zero status code.
   *
   * Most of this code is blocking a procedural and this can be communicated to
   * the caller via Errata. But the HTTP/2 nghttp2 callbacks do not return
   * directly to a caller. Therefore this is used to communicate a non-zero
   * status.
   */
  static void set_non_zero_exit_status();

  /** Perform the HTTP/3 (ngtcp2 and nghttp3) configuration and QUIC handshake
   * for a client connection. */
  swoc::Errata client_session_init();

  /** Perform the HTTP/3 (ngtcp2 and nghttp3) configuration for a server
   * connection. */
  swoc::Errata server_session_init();

  /** Run all the transactions against the specified target. */
  swoc::Errata run_transactions(
      std::list<Txn> const &transactions,
      swoc::TextView interface,
      swoc::IPEndpoint const *target,
      double rate_multiplier) override;

  /** Replay the given transaction for this session. */
  swoc::Errata run_transaction(Txn const &transaction) override;

  /** Indicate that the stream has ended (received the END_STREAM flag).
   *
   * @param[in] stream_id The stream identifier for which the end stream has
   * been processed.
   *
   * @param[in] key The key for the stream which ended.
   */
  void set_stream_has_ended(int64_t stream_id, std::string_view key);

  /// Whether an entire stream has been received and is ready for processing.
  bool get_a_stream_has_ended() const;

  void record_stream_state(int64_t stream_id, std::shared_ptr<H3StreamState> stream_state);

public:
  /// A mapping from stream_id to H3StreamState.
  std::unordered_map<int64_t, std::shared_ptr<H3StreamState>> stream_map;

  /// The representation of the QUIC socket for this stream (connection).
  QuicSocket quic_socket;

protected:
  /** Initialize the client-side SSL_CTS used across all connections. */
  static swoc::Errata client_ssl_ctx_init(SSL_CTX *&client_context);

  /** Initialize the server-side SSL_CTS used across all connections. */
  static swoc::Errata server_ssl_ctx_init(SSL_CTX *&server_context);
  static void terminate(SSL_CTX *&client_context);

protected:
  /** The SNI to be sent by the client (as opposed to the one expected by the
   * server from the proxy). This only applies to the client.
   */
  std::string _client_sni;

  /** The verify mode for the client in the TLS handshake with the proxy.
   * This only applies to the client.
   */
  int _client_verify_mode = SSL_VERIFY_NONE;

  SSL *_ssl = nullptr;

private:
  nghttp3_nv tv_to_nv(char const *name, swoc::TextView v);

  /** Create and configure the UDP socket for this connection. */
  swoc::Errata configure_udp_socket(swoc::TextView interface, swoc::IPEndpoint const *target);

  /** Create and configure the SSL instance for this session. */
  swoc::Errata client_ssl_session_init(SSL_CTX *client_context);

  swoc::Errata receive_responses();

  /** Determine whether the transaction is still awaiting upon other configured streams.
   *
   * @param[in] txn The transaction to check.
   * @return Whether the transaction is still awaiting upon other configured streams.
   */
  bool request_has_outstanding_stream_dependencies(HttpHeader const &request) const;

private:
  /** The streams which have completed */
  std::deque<int64_t> _ended_streams;
  swoc::IPEndpoint const *_endpoint = nullptr;

  std::shared_ptr<H3StreamState> _last_added_stream;

  /// The set of streams which have completed already.
  std::unordered_set<std::string> _finished_streams;

  /** The client context to use for HTTP/3 connections.
   *
   * This is used per HTTP/3 connection so that ALPN advertises h3. For HTTP/1
   * TLS connections, client_context is used which does not advertise h2
   * support.
   */
  static SSL_CTX *_h3_client_context;

  /** The client context to use for HTTP/3 connections.
   *
   * This is used per HTTP/3 connection so that ALPN advertises h3. For HTTP/1
   * TLS connections, client_context is used which does not advertise h2
   * support.
   */
  static SSL_CTX *_h3_server_context;

  /// The system status code. This is set to non-zero if problems are detected.
  static int *process_exit_code;
};
