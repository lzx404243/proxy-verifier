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

/// PROXY header v1 end of header.
static constexpr swoc::TextView PROXY_V1_EOH{"\r\n"};

const char v2sig[12] = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
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
      //   struct
      //   { /* for AF_UNIX sockets, len = 216 */
      //     uint8_t src_addr[108];
      //     uint8_t dst_addr[108];
      //   } unx;
    } addr;
  } v2;
};

class ProxyProtocolUtil
{
public:
  // TODO: changed to unique pointer
  ProxyProtocolUtil(std::shared_ptr<ProxyHdr> data) : _hdr(data){};
  // parse the header, returning the number of bytes if it is a valid header, or
  // 0 if it is not a PROXY header
  swoc::Rv<ssize_t> parse_header(ssize_t receivedBytes);

  int get_version() const;
  // TODO: change the  access level back to private
public:
  std::shared_ptr<ProxyHdr> _hdr;
  int _version = 0;
};

inline int
ProxyProtocolUtil::get_version() const
{
  return _version;
}
