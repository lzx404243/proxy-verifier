#include "core/proxy_protocol_util.h"
#include "core/ProxyVerifier.h"
#include <codecvt>
#include <locale>

using swoc::Errata;
using swoc::TextView;

swoc::Rv<int>
ProxyProtocolHdr::parse_header(swoc::TextView data)
{
  swoc::Rv<int> zret{-1};
  ProxyHdr hdr;

  // find the end of the header
  if (data.starts_with("PROXY")) {
    zret.note(S_DIAG, "got proxy protocol version 1");
    // check header end
    size_t end = data.find("\r\n");
    if (TextView::npos != end) {
      zret.note(S_DIAG, "find header end at {}", end);
      zret = end + PROXY_V1_EOH.size();
      return zret;
    }
  } else {
    zret.note(S_DIAG, "not found proxy protocol version 1");
    zret = 0;
    return zret;
  }

  std::memcpy(&hdr, data.data(), sizeof(hdr));
  if (data.size() >= 16 && memcmp(&hdr.v2, v2sig, 12) == 0 && (hdr.v2.ver_cmd & 0xF0) == 0x20) {
    zret.note(S_DIAG, "got proxy protocol version 2");
    // size = 16 + ntohs(hdr.v2.len);
    // if (ret < size)
    //   return -1; /* truncated or too large header */

    switch (hdr.v2.ver_cmd & 0xF) {
    case 0x01: /* PROXY command */
      switch (hdr.v2.fam) {
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
      zret.note(S_ERROR, "unknown command!");
      return zret; /* not a supported command */
    }
    zret = 1;
    return zret;
  } else if (data.size() >= 8 && memcmp(hdr.v1.line, "PROXY", 5) == 0) {
    zret.note(S_DIAG, "I got proxy protocol version 1");
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    std::wstring decoded_string = converter.from_bytes(hdr.v1.line);

    std::cout << "proxy protocol header content " << std::endl;
    std::wcout << decoded_string << std::endl;
    // zret.note(S_INFO, "proxy protocol header content {}", decoded_string);
    zret = 1;
    return zret;
  } else {
    /* Wrong protocol */
    // zret.note(S_ERROR, "not proxy protocol!");
    return zret;
  }
  return zret;
}
