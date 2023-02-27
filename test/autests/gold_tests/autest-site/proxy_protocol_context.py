import socket
import io
import struct
import time
import ssl
# ProxyProtocolCtx is a wrapper around the socket object that is used to append/strip off the proxy protocol header.

PP_V2_PREFIX = b'\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a'
# The maximum size of the proxy protocol header is 108 bytes(assuming TLV and
# linux socket address are not used)
PP_MAX_DATA_SIZE = 108


class SocketFileWrapper(io.RawIOBase):
    def __init__(self, sock, mode, buffering, use_ssl=False, ssl_ctx=None, server_side=False):
        self.sock = sock
        self.file = sock.makefile(mode, buffering)
        self._buffering = buffering
        self._file_mode = mode
        self._check_for_pp_header = True
        self._is_server_side = server_side
        self._use_ssl = use_ssl
        self._ssl_ctx = ssl_ctx
        self.paired_wfile = None

    def check_for_proxy_header(self, data):
        # check for proxy protocol header. Most of the code here is borrowed from Brian Neradt's proxy_protocol_server in ATS repo
        #print("checking for proxy protocol header")
        pp_length = 0
        if (data.startswith(b'PROXY') and b'\r\n' in data):
            pp_length = parse_pp_v1(data)
            print(f"Received {pp_length} bytes of Proxy Protocol v1")

        if data.startswith(PP_V2_PREFIX):
            pp_length = parse_pp_v2(data)
            print(f"Received {pp_length} bytes of Proxy Protocol v2")
        return pp_length

    def read_pp_header_if_present(self):
        # peek at the file content to check for proxy protocol header
        print("checking for proxy protocol header")
        data = self.file.peek(PP_MAX_DATA_SIZE)
        pp_bytes = self.check_for_proxy_header(data)
        if pp_bytes > 0:
            # read the pp header bytes from the file
            print(f"reading {pp_bytes} bytes from the file")
            self.file.read(pp_bytes)
        return

    def read(self, size):
        print("calling read method!")
        if self._check_for_pp_header:
            # happens only once
            self.read_pp_header_if_present()
            self._check_for_pp_header = False
            if self._use_ssl and self.is_server_side:
                print("wrapping the socket with ssl")
                self.wrapSSL(self._ssl_ctx)
                print("done SSL wrapping!")
        data = self.file.read(size)
        print(f"data content: {data}")
        return data

    def readline(self, size):
        print("calling the readline method!")
        if self._check_for_pp_header:
            # happens only once
            self.read_pp_header_if_present()
            self._check_for_pp_header = False
            if self._use_ssl:
                print("wrapping the socket with ssl")
                self.wrapSSL()
                print("done SSL wrapping!")
        # print("printing out stuff")
        # data = self.file.peek(100000)
        # print(f"peeked data: {data}")
        data = self.file.readline(size)
        print(f"data content: {data}")
        return data

    def wrapSSL(self):
        self.sock = self._ssl_ctx.wrap_socket(
            self.sock, server_side=True)
        # TODO: double check the file mode and buffering mode
        print("updating the new file objects")
        self.file = self.sock.makefile(self._file_mode, self._buffering)
        self.paired_wfile.sock = self.sock
        self.paired_wfile.file = self.sock.makefile('wb', self._buffering)

    def write(self, b):
        return self.sock.sendall(b)
        # return self.file.write(b)

    def close(self):
        self.file.close()
    # TODO: check write logic also


class ProxyProtocolCtx(socket.socket):
    def __init__(self, server_side, client_sock=None, use_ssl=False, ssl_ctx=None):
        self._socket = None
        self._client_socket = client_sock
        self._server_side = server_side
        self._done_pp_processing = False
        self._use_ssl = use_ssl
        self._ssl_ctx = ssl_ctx
        self.rfile = None
        self.wfile = None
        super().__init__()

    def wrap_socket(self, sock):

        # TODO: learn strucuture from ssl lib: return self.sslsocket_class._create(
        self._socket = sock
        if not self._server_side:
            self._client_socket = sock
            # for client-side socket, we send the proxy protocol header to the original underlying socket right way.
            # TODO: have a flag to control this behavior. The flag should be set to true if the proxy protocol header is received by the proxy
            send_proxy_header(self._client_socket, proxy_protocol_version=1)
        return self

    def getsockname(
        self, *args, **kwargs): return self._socket.getsockname(*args, **kwargs)

    def fileno(self):
        # TODO: may need to change this for the wfile to work. _socket would be replaced with the client socket
        print("calling the overridden fileno method")
        return self._client_socket.fileno() if self._client_socket else self._socket.fileno()

    def accept(self):
        print("calling the overridden accept method")
        client_sock, client_addr = self._socket.accept()
        # TODO: create a new ProxyProtocolCtx object here. see if there is a better way to do this
        return ProxyProtocolCtx(server_side=True, client_sock=client_sock, use_ssl=self._use_ssl, ssl_ctx=self._ssl_ctx), client_addr

    def create_connection(address, timeout, source_address):
        raise NotImplementedError("create_connection is not implemented")

    def send(self, data):
        raise NotImplementedError("send is not implemented")
        # print("calling the overridden send method")
        # return self._socket.send(data)

    def recv(self, size):
        raise NotImplementedError("recv is not implemented")
        # print("calling the overridden recv method")
        # return self._socket.recv(size)

    def sendall(self, data):
        print("calling the overridden sendall method")
        return self._client_socket.sendall(data)

    def makefile(self, mode="r", buffering=None):
        print("proxy ctx makefile is called")
        if 'r' in mode:
            print("creating the rfile")
            self.rfile = SocketFileWrapper(
                self._client_socket, mode, buffering, self._use_ssl, self._ssl_ctx, self._server_side)
            return self.rfile
        elif 'w' in mode:
            print("creating the wfile")
            self.wfile = SocketFileWrapper(
                self._client_socket, mode, buffering, self._use_ssl, self._ssl_ctx, self._server_side)
            if self.rfile:
                print("assigning the paired wfile in the rfile")
                self.rfile.paired_wfile = self.wfile
            return self.wfile

    def shutdown(self, how):
        return self._client_socket.shutdown(how)

    def close(self):
        return self._client_socket.close()

    def detach(self):
        """detach() -> file descriptor
        Close the socket object without closing the underlying file descriptor.
        The object cannot be used after this call, but the file descriptor
        can be reused for other purposes.  The file descriptor is returned.
        """
        self._closed = True
        detached_fd = super().detach()
        if self._client_socket is not None:
            return self._client_socket.detach()
        return detached_fd


# utility methods for parsing or encoding the PROXY protocol header
def parse_pp_v1(pp_bytes: bytes) -> int:
    """Parse and print the Proxy Protocol v1 string.
    :param pp_bytes: The bytes containing the Proxy Protocol string. There may
    be more bytes than the Proxy Protocol string.
    :returns: The number of bytes occupied by the proxy v1 protocol.
    """
    # Proxy Protocol v1 string ends with CRLF.
    end = pp_bytes.find(b'\r\n')
    if end == -1:
        raise ValueError("Proxy Protocol v1 string ending not found")
    print(pp_bytes[:end].decode("utf-8"))
    return end + 2


def parse_pp_v2(pp_bytes: bytes) -> int:
    """Parse and print the Proxy Protocol v2 string.
    :param pp_bytes: The bytes containing the Proxy Protocol string. There may
    be more bytes than the Proxy Protocol string.
    :returns: The number of bytes occupied by the proxy v2 protocol string.
    """

    # Skip the 12 byte header.
    pp_bytes = pp_bytes[12:]
    version_command = pp_bytes[0]
    pp_bytes = pp_bytes[1:]
    family_protocol = pp_bytes[0]
    pp_bytes = pp_bytes[1:]
    tuple_length = int.from_bytes(pp_bytes[:2], byteorder='big')
    pp_bytes = pp_bytes[2:]

    # Of version_command, the highest 4 bits is the version and the lowest is
    # the command.
    version = version_command >> 4
    command = version_command & 0x0F

    if version != 2:
        raise ValueError(
            f'Invalid version: {version} (by spec, should always be 0x02)')

    if command == 0x0:
        command_description = 'LOCAL'
    elif command == 0x1:
        command_description = 'PROXY'
    else:
        raise ValueError(
            f'Invalid command: {command} (by spec, should be 0x00 or 0x01)')

    # Of address_family, the highest 4 bits is the address family and the
    # lowest is the transport protocol.
    if family_protocol == 0x0:
        transport_protocol_description = 'UNSPEC'
    elif family_protocol == 0x11:
        transport_protocol_description = 'TCP4'
    elif family_protocol == 0x12:
        transport_protocol_description = 'UDP4'
    elif family_protocol == 0x21:
        transport_protocol_description = 'TCP6'
    elif family_protocol == 0x22:
        transport_protocol_description = 'UDP6'
    elif family_protocol == 0x31:
        transport_protocol_description = 'UNIX_STREAM'
    elif family_protocol == 0x32:
        transport_protocol_description = 'UNIX_DGRAM'
    else:
        raise ValueError(
            f'Invalid address family: {family_protocol} (by spec, should be '
            '0x00, 0x11, 0x12, 0x21, 0x22, 0x31, or 0x32)')

    if family_protocol in (0x11, 0x12):
        if tuple_length != 12:
            raise ValueError(
                "Unexpected tuple length for TCP4/UDP4: "
                f"{tuple_length} (by) spec, should be 12)"
            )
        src_addr = socket.inet_ntop(socket.AF_INET, pp_bytes[:4])
        pp_bytes = pp_bytes[4:]
        dst_addr = socket.inet_ntop(socket.AF_INET, pp_bytes[:4])
        pp_bytes = pp_bytes[4:]
        src_port = int.from_bytes(pp_bytes[:2], byteorder='big')
        pp_bytes = pp_bytes[2:]
        dst_port = int.from_bytes(pp_bytes[:2], byteorder='big')
        pp_bytes = pp_bytes[2:]

    tuple_description = f'{src_addr} {dst_addr} {src_port} {dst_port}'
    print(
        f'{command_description} {transport_protocol_description} '
        f'{tuple_description}')

    return 16 + tuple_length


# TODO: correct PROXY protocol format to include IP protocol version
def construct_proxy_header_v1(src_addr, dst_addr):
    # Construct the PROXY protocol v1 header
    # TODO: remove the commented code
    # header = f"PROXY {src_addr[0]} {dst_addr[0]} {src_addr[1]} {dst_addr[1]}\r\n".encode(
    # )
    # print(f'proxy header: {header}')
    return f"PROXY {src_addr[0]} {dst_addr[0]} {src_addr[1]} {dst_addr[1]}\r\n".encode()


def construct_proxy_header_v2(src_addr, dst_addr):
    # Construct the PROXY protocol v2 header
    header = PP_V2_PREFIX
    # Protocol version 2 + PROXY command
    header += b'\x21'
    # TCP over IPv4
    header += b'\x11'
    # address length
    header += b'\x00\x0C'
    header += socket.inet_pton(socket.AF_INET, src_addr[0])
    header += socket.inet_pton(socket.AF_INET, dst_addr[0])
    header += struct.pack('!H', src_addr[1])
    header += struct.pack('!H', dst_addr[1])
    return header


def send_proxy_header(sock, proxy_protocol_version):
    # get source ip and port from socket
    print(f'Sending PROXY protocol version {proxy_protocol_version}')
    proxy_header_construcut_func = construct_proxy_header_v1 if proxy_protocol_version == 1 else construct_proxy_header_v2
    proxy_header_data = proxy_header_construcut_func(
        sock.getsockname(), sock.getpeername())
    sock.sendall(proxy_header_data)
    # TODO: may be reduce or remove
    time.sleep(1)
