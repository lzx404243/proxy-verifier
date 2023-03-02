/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "swoc/Errata.h"
#include "swoc/BufferWriter.h"
#include "swoc/TextView.h"
#include "swoc/swoc_ip.h"

enum class ProxyProtocolVersion { NONE = 0, V1 = 1, V2 = 2 };

/// PROXY header v1 end of header.
static constexpr swoc::TextView PROXY_V1_EOH{"\r\n"};

static constexpr size_t MAX_PP_HDR_SIZE = 108;

static constexpr char PP_V1_DELIMITER = ' ';

static const swoc::TextView V1SIG("PROXY");
// static const swoc::TextView V2SIG(
//     reinterpret_cast<const char *>(
//         "0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A"),
//     12);
using namespace std::literals;

constexpr swoc::TextView V2SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"sv;
// const char V2SIGOLD[12] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
// 0x0A};

union ProxyHdr {
  struct
  {
    char line[108];
  } v1;
  struct
  {
    uint8_t sig[12];
    uint8_t ver_cmd;
    uint8_t fam;
    uint16_t len;
    union {
      struct
      { /* for TCP/UDP over IPv4, len = 12 */
        uint32_t src_addr;
        uint32_t dst_addr;
        uint16_t src_port;
        uint16_t dst_port;
      } ip4;
      struct
      { /* for TCP/UDP over IPv6, len = 36 */
        uint8_t src_addr[16];
        uint8_t dst_addr[16];
        uint16_t src_port;
        uint16_t dst_port;
      } ip6;
    } addr;
  } v2;
};

// TODO: rename to proxyProtocol
class ProxyProtocolUtil
{
public:
  ProxyProtocolUtil() = default;
  ProxyProtocolUtil(ProxyProtocolVersion version) : _version(version){};
  ProxyProtocolUtil(swoc::IPEndpoint src_ep, swoc::IPEndpoint dst_ep, ProxyProtocolVersion version)
    : _version(version)
    , _src_addr(src_ep)
    , _dst_addr(dst_ep){};

  // parse the header, returning the number of bytes if it is a valid header, or
  // 0 if it is not a PROXY header
  swoc::Rv<ssize_t> parse_header(swoc::TextView data);

  ProxyProtocolVersion get_version() const;
  swoc::Errata serialize(swoc::BufferWriter &buf) const;
  swoc::Errata construct_v1_header(swoc::BufferWriter &buf) const;
  swoc::Errata construct_v2_header(swoc::BufferWriter &buf) const;
  // TODO: change the  access level back to private
public:
  ProxyProtocolVersion _version = ProxyProtocolVersion::NONE;
  swoc::IPEndpoint _src_addr;
  swoc::IPEndpoint _dst_addr;

private:
  swoc::Rv<ssize_t> parse_pp_header_v1(swoc::TextView data);

  swoc::Rv<ssize_t> parse_pp_header_v2(swoc::TextView data);
};

inline ProxyProtocolVersion
ProxyProtocolUtil::get_version() const
{
  return _version;
}
