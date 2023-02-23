#include "core/proxy_protocol_util.h"
#include "core/ProxyVerifier.h"
#include <codecvt>
#include <locale>
#include "swoc/bwf_ex.h"

using swoc::Errata;
using swoc::TextView;

swoc::Rv<ssize_t>
ProxyProtocolUtil::parse_header(ssize_t receivedBytes)
{
  swoc::Rv<ssize_t> zret{-1};
  // // find the end of the header
  // if (data.starts_with("PROXY")) {
  //   zret.note(S_DIAG, "got proxy protocol version 1");
  //   // check header end
  //   size_t end = data.find("\r\n");
  //   if (TextView::npos != end) {
  //     zret.note(S_DIAG, "find header end at {}", end);
  //     zret = end + PROXY_V1_EOH.size();
  //     return zret;
  //   }
  // } else {
  //   zret.note(S_DIAG, "not found proxy protocol version 1");
  //   zret = 0;
  //   return zret;
  // }
  int size = 0;
  if (receivedBytes >= 16 && memcmp(&_hdr->v2, V2SIG, 12) == 0 && (_hdr->v2.ver_cmd & 0xF0) == 0x20)
  {
    _version = ProxyProtocolVersion::V2;
    size = 16 + ntohs(_hdr->v2.len);
    zret = size;
    // zret.note(S_DIAG, "got proxy protocol version 2");
    //  size = 16 + ntohs(hdr.v2.len);
    //  if (ret < size)
    //    return -1; /* truncated or too large header */

    switch (_hdr->v2.ver_cmd & 0xF) {
    case 0x01: /* PROXY command */
      switch (_hdr->v2.fam) {
      case 0x11: /* TCPv4 */
        zret.note(S_DIAG, "TCPv4");
        break;
      case 0x21: /* TCPv6 */
        zret.note(S_DIAG, "TCPv6");
        break;
      default:
        /* unsupported protocol, keep local connection address */
        zret.note(S_ERROR, "unknown transport!");
        break;
      }
      break;
    case 0x00: /* LOCAL command */
      /* keep local connection address for LOCAL */
      zret.note(S_DIAG, "local command");
      break;
    default:
      zret = -1;
      zret.note(S_ERROR, "unknown command!");
      return zret; /* not a supported command */
    }
  } else if (receivedBytes >= 8 && memcmp(_hdr->v1.line, "PROXY", 5) == 0) {
    _version = ProxyProtocolVersion::V1;
    // zret.note(S_DIAG, "I got proxy protocol version 1");
    char *end = (char *)memchr(_hdr->v1.line, '\r', receivedBytes - 1);
    if (!end || end[1] != '\n') {
      zret.note(S_ERROR, "not found header end!");
      return zret; /* partial or invalid header */
    }
    *end = '\0';                    /* terminate the string to ease parsing */
    size = end + 2 - _hdr->v1.line; /* skip header + CRLF */
    zret = size;
    // std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    // std::wstring decoded_string = converter.from_bytes(_hdr->v1.line);
    // std::cout << "proxy protocol header content " << std::endl;
    // std::wcout << decoded_string << std::endl;
    // zret.note(S_INFO, "proxy protocol header content {}", decoded_string);
    return zret;
  } else {
    /* Wrong protocol */
    zret.note(S_DIAG, "not proxy protocol. Passing through");
    return zret;
  }
  return zret;
}

swoc::Errata
ProxyProtocolUtil::serialize(swoc::BufferWriter &buf) const
{
  swoc::Errata errata;
  if (_version == ProxyProtocolVersion::V1) {
    return construct_v1_header(buf);
  } else if (_version == ProxyProtocolVersion::V2) {
    return construct_v2_header(buf);
  }
  errata.note(S_ERROR, "unknown proxy protocol version!");
  return errata;
};

swoc::Errata
ProxyProtocolUtil::construct_v1_header(swoc::BufferWriter &buf) const
{
  swoc::Errata errata;
  buf.print(
      "PROXY {}{} {2::a} {3::a} {2::p} {3::p}\r\n",
      swoc::bwf::If(_src_addr.is_ip4(), "TCP4"),
      swoc::bwf::If(_src_addr.is_ip6(), "TCP6"),
      _src_addr,
      _dst_addr);
  errata.note(S_INFO, "construcuting proxy protocol v1 header content {}", buf);
  return errata;
}

swoc::Errata
ProxyProtocolUtil::construct_v2_header(swoc::BufferWriter &buf) const
{
  swoc::Errata errata;
  ProxyHdr proxy_hdr;
  memcpy(proxy_hdr.v2.sig, V2SIG, sizeof(V2SIG));
  // only support the PROXY command for now
  proxy_hdr.v2.ver_cmd = 0x21;
  if (_src_addr.is_ip4()) {
    proxy_hdr.v2.fam = 0x11;
    proxy_hdr.v2.len = htons(sizeof(proxy_hdr.v2.addr.ip4));
    proxy_hdr.v2.addr.ip4.src_addr = _src_addr.sa4.sin_addr.s_addr;
    proxy_hdr.v2.addr.ip4.dst_addr = _dst_addr.sa4.sin_addr.s_addr;
    proxy_hdr.v2.addr.ip4.src_port = _src_addr.network_order_port();
    proxy_hdr.v2.addr.ip4.dst_port = _dst_addr.network_order_port();
  } else {
    // ipv6
    proxy_hdr.v2.fam = 0x21;
    proxy_hdr.v2.len = htons(sizeof(proxy_hdr.v2.addr.ip6));
    memcpy(
        proxy_hdr.v2.addr.ip6.src_addr,
        reinterpret_cast<const uint8_t *>(&_src_addr.sa6.sin6_addr),
        16);
    memcpy(
        proxy_hdr.v2.addr.ip6.dst_addr,
        reinterpret_cast<const uint8_t *>(&_src_addr.sa6.sin6_addr),
        16);
    proxy_hdr.v2.addr.ip6.src_port = _src_addr.network_order_port();
    proxy_hdr.v2.addr.ip6.dst_port = _dst_addr.network_order_port();
  }
  // buf.print(
  //     "PROXY {}{} {2::a} {3::a} {2::p} {3::p}\r\n",
  //     swoc::bwf::If(_src_addr.is_ip4(), "TCP4"),
  //     swoc::bwf::If(_src_addr.is_ip6(), "TCP6"),
  //     _src_addr,
  //     _dst_addr);
  buf.write(&proxy_hdr, proxy_hdr.v2.len + 16);
  errata.note(S_INFO, "construcuting proxy protocol v2 header content {}", buf);
  return errata;
}
