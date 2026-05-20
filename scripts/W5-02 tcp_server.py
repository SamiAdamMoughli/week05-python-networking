"""Multi-client TCP server with broadcast, chat handler, and TCP client."""

import logging
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.append("../../week04-python-web/scripts")
from requests_client import SecureLogger


class TCPServer:
    """Thread-per-client TCP server with broadcast and graceful shutdown."""

    def __init__(self, host: str, port: int, max_clients: int = 10) -> None:
        """
        Args:
            host: Interface to bind to.
            port: Port to listen on.
            max_clients: Maximum concurrent connections before refusing new ones.
        """
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients: dict = {}
        self._stop_event = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=max_clients)
        self.logger = SecureLogger(__name__)

    def start(self) -> None:
        """Bind, listen, and accept clients in a loop until stop() is called.

        Raises:
            RuntimeError: If bind or listen fails.
        """
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(self.max_clients)
        except OSError as e:
            raise RuntimeError(
                f"Server failed to start on {self.host}:{self.port}"
            ) from e

        try:
            while not self._stop_event.is_set():
                try:
                    conn, addr = self.socket.accept()
                    if len(self.clients) >= self.max_clients:
                        conn.sendall(b"Server full. Try again later.")
                        conn.close()
                        continue
                    self.clients[conn] = addr
                    self._executor.submit(self._handle_client, conn, addr)
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise
        finally:
            self.socket.close()

    def stop(self) -> None:
        """Signal the server to stop and close all active connections."""
        self._stop_event.set()
        try:
            self.socket.close()
            print("Server stopped.")
        except OSError:
            pass
        for conn in list(self.clients):
            try:
                conn.close()
            except OSError:
                pass
        self.clients.clear()
        self._executor.shutdown(wait=False)

    def _handle_client(self, conn: socket.socket, addr: tuple) -> None:
        """Echo all received data back to the sender until disconnect."""
        self._log_connection(addr, "connected")
        try:
            with conn:
                while data := conn.recv(1024):
                    conn.sendall(data)
        except OSError as e:
            print(f"Client {addr} error: {e}")
        finally:
            self.clients.pop(conn, None)
            self._log_connection(addr, "disconnected")

    def broadcast(self, message: str) -> None:
        """Send message to all connected clients. Dead clients are silently removed."""
        for conn in list(self.clients):
            try:
                conn.sendall(message.encode("utf-8"))
            except (OSError, ConnectionResetError):
                self.clients.pop(conn, None)

    def _log_connection(self, addr: tuple, event: str) -> None:
        """Log a client connect or disconnect event."""
        self.logger.info(f"Client {addr[0]}:{addr[1]} {event}")


class ChatHandler(TCPServer):
    """TCPServer subclass that prepends sender IP and broadcasts to all clients.

    Enforces 1024 byte message limit and disconnects idle clients after 60 seconds.
    """

    def _handle_client(self, conn: socket.socket, addr: tuple) -> None:
        """Read messages, truncate if over 1024 bytes, broadcast to all clients."""
        self._log_connection(addr, "connected")
        try:
            with conn:
                conn.settimeout(60)
                while data := conn.recv(1024):
                    if len(data) > 1024:
                        data = data[:1024]
                        self.logger.warning(
                            f"Message from {addr[0]} truncated to 1024 bytes"
                        )
                    message = f"{addr[0]}: {data.decode('utf-8', errors='replace')}"
                    self.broadcast(message=message)
        except TimeoutError:
            self.logger.info(f"Client {addr[0]} timed out")
        except OSError as e:
            self.logger.error(f"Client {addr[0]} error: {e}")
        finally:
            self.clients.pop(conn, None)
            self._log_connection(addr, "disconnected")


class TCPClient:
    """Stateful TCP client with connect, send, receive, and disconnect."""

    def __init__(self, host: str, port: int) -> None:
        """
        Args:
            host: Server host to connect to.
            port: Server port to connect to.
        """
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None

    def connect(self) -> None:
        """Open a TCP connection to the server.

        Raises:
            RuntimeError: If the connection fails.
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5.0)
            self.socket.connect((self.host, self.port))
        except OSError as e:
            raise RuntimeError(f"Failed to connect to {self.host}:{self.port}") from e

    def send(self, message: str) -> None:
        """Send a UTF-8 encoded message to the server.

        Raises:
            RuntimeError: If not connected or send fails.
            ValueError: If message is empty.
        """
        if self.socket is None:
            raise RuntimeError("Not connected. Call connect() first.")
        if not message:
            raise ValueError("Message cannot be empty.")
        try:
            self.socket.sendall(message.encode("utf-8"))
        except OSError as e:
            raise RuntimeError(f"Send failed: {e}") from e

    def receive(self, timeout: float = 5.0) -> str:
        """Read up to 1024 bytes from the server.

        Args:
            timeout: Seconds to wait before raising RuntimeError.
        Returns:
            Decoded response string. Invalid bytes replaced.
        Raises:
            RuntimeError: If not connected, timed out, or receive fails.
        """
        if self.socket is None:
            raise RuntimeError("Not connected. Call connect() first.")
        self.socket.settimeout(timeout)
        try:
            data = self.socket.recv(1024)
            return data.decode("utf-8", errors="replace")
        except TimeoutError as e:
            raise RuntimeError("Receive timed out.") from e
        except OSError as e:
            raise RuntimeError(f"Receive failed: {e}") from e

    def disconnect(self) -> None:
        """Close the connection and reset socket to None."""
        if self.socket is None:
            return
        try:
            self.socket.close()
        except OSError:
            pass
        finally:
            self.socket = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    HOST = "127.0.0.1"
    PORT = 9500

    server = ChatHandler(HOST, PORT)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    def client_session(client_id: int) -> None:
        """Connect, send 3 messages, receive broadcasts, disconnect."""
        client = TCPClient(HOST, PORT)
        client.connect()
        for i in range(3):
            msg = f"Client {client_id} message {i + 1}"
            client.send(msg)
            client.receive()
            time.sleep(0.1)
        client.disconnect()

    threads = []
    for i in range(3):
        t = threading.Thread(target=client_session, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    time.sleep(1)
    server.stop()
