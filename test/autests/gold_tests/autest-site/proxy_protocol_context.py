import socket
import io
# ProxyProtocolCtx is a wrapper around the socket object that is used to append/strip off the proxy protocol header.


class SocketFileWrapper(io.RawIOBase):
    def __init__(self, sock, mode, buffering):
        self.sock = sock
        self.file = sock.makefile(mode, buffering)

    def read(self, size):
        data = self.file.read(size)
        print("calling the overriden file object read method!")
        print("doint magic!")
        # Your processing logic here
        return data

    def readline(self, size):
        print("calling the overriden file object readline method!")
        print("doint magic!")
        # Your processing logic here
        return self.file.readline(size)

    def close(self):
        self.file.close()


class ProxyProtocolCtx(socket.socket):
    # class ppSocket(socket.socket):
    #     # declare class member variable

    def wrap_socket(self, sock, server_side=False):
        self._socket = sock
        return self

    def getsockname(self, *args, **kwargs):
        return self._socket.getsockname(*args, **kwargs)

    def fileno(self):
        # todo: may need to change this for the wfile to work
        return self._socket.fileno()

    def accept(self):
        self._client_socket, client_addr = self._socket.accept()
        return self, client_addr
        # not sure if this is required. Can't we just return the _socket.accept()?
        # return self.__class__(client_sock), client_addr
        # return self._socket.accept()

    def send(self, data):
        print("calling the overridden send method")
        return self._socket.send(data)

    def recv(self, size):
        print("calling the overridden recv method")
        return self._socket.recv(size)

    def sendall(self, data):
        print("calling the overridden sendall method")
        return self._client_socket.sendall(data)

    def makefile(self, mode, buffering):
        print("proxy ctx makefile is called")
        return SocketFileWrapper(self._client_socket, mode, buffering)

    def shutdown(self, how):
        return self._client_socket.shutdown(how)

    def close(self):
        return self._client_socket.close()
