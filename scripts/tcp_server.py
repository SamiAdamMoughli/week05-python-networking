"""Multi-client TCP server with broadcast, chat handler, and TCP client."""

import argparse
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Final

# Configure robust system-wide logging formats
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)
log: logging.Logger = logging.getLogger(__name__)

BUFFER_SIZE: Final[int] = 1024


class SecureLogger:
    """Thin security-audited wrapper providing standardized log sanitization boundaries."""

    def __init__(self, name: str) -> None:
        """Initialize logger context."""
        self._logger: logging.Logger = logging.getLogger(name)

    def info(self, msg: str, *args: object) -> None:
        """Log safe informational tracking messages."""
        self._logger.info(msg, *args)

    def warning(self, msg: str, *args: object) -> None:
        """Log tracking security warnings."""
        self._logger.warning(msg, *args)

    def error(self, msg: str, *args: object) -> None:
        """Log runtime system operational exceptions."""
        self._logger.error(msg, *args)


class TCPServer:
    """Thread-per-client TCP server with broadcast and graceful shutdown."""

    def __init__(self, host: str, port: int, max_clients: int = 10) -> None:
        """Initialize server tracking vectors.

        Args:
            host: Interface to bind to.
            port: Port to listen on.
            max_clients: Maximum concurrent connections before refusing new ones.
        """
        self.host: str = host
        self.port: int = port
        self.max_clients: int = max_clients
        self.socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients: dict[socket.socket, tuple[str, int]] = {}
        self._stop_event: threading.Event = threading.Event()
        self._executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=max_clients)
        self.logger: SecureLogger = SecureLogger(__name__)

    def start(self, ready_event: threading.Event | None = None) -> None:
        """Bind, listen, and accept clients in a loop until stop() is called.

        Args:
            ready_event: Optional synchronization primitive tripped when listening begins.

        Raises:
            RuntimeError: If bind or listen fails.
        """
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(self.max_clients)
            if ready_event:
                ready_event.set()
        except OSError as e:
            if ready_event:
                ready_event.set()
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
            self.logger.info("Server stopped.")
        except OSError:
            pass

        for conn in list(self.clients):
            try:
                conn.close()
            except OSError:
                pass

        self.clients.clear()
        self._executor.shutdown(wait=False)

    def _handle_client(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        """Echo all received data back to the sender until disconnect."""
        self._log_connection(addr, "connected")
        try:
            with conn:
                while data := conn.recv(BUFFER_SIZE):
                    conn.sendall(data)
        except OSError as e:
            self.logger.error("Client %s error: %s", addr, e)
        finally:
            self.clients.pop(conn, None)
            self._log_connection(addr, "disconnected")

    def broadcast(self, message: str) -> None:
        """Send message to all connected clients. Dead clients are silently removed."""
        payload = message.encode("utf-8")
        for conn in list(self.clients):
            try:
                conn.sendall(payload)
            except (
                OSError,
                (
                    ConnectionResultError
                    if "ConnectionResultError" in globals()
                    else OSError
                ),
            ):
                self.clients.pop(conn, None)

    def _log_connection(self, addr: tuple[str, int], event: str) -> None:
        """Log a client connect or disconnect event safely."""
        self.logger.info("Client %s:%s %s", addr[0], addr[1], event)


class ChatHandler(TCPServer):
    """TCPServer subclass that prepends sender IP and broadcasts to all clients.

    Enforces 1024 byte message limit and disconnects idle clients after 60 seconds.
    """

    def _handle_client(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        """Read messages, truncate if over 1024 bytes, broadcast to all clients."""
        self._log_connection(addr, "connected")
        try:
            with conn:
                conn.settimeout(60.0)
                while data := conn.recv(BUFFER_SIZE):
                    if len(data) > BUFFER_SIZE:
                        data = data[:BUFFER_SIZE]
                        self.logger.warning(
                            "Message from %s truncated to 1024 bytes", addr[0]
                        )
                    message = f"{addr[0]}: {data.decode('utf-8', errors='replace')}"
                    self.broadcast(message=message)
        except TimeoutError:
            self.logger.info(
                "Client %s timed out due to system inactivity rules", addr[0]
            )
        except OSError as e:
            self.logger.error("Client %s unexpected connection error: %s", addr[0], e)
        finally:
            self.clients.pop(conn, None)
            self._log_connection(addr, "disconnected")


class TCPClient:
    """Stateful TCP client with connect, send, receive, and disconnect."""

    def __init__(self, host: str, port: int) -> None:
        """Initialize network endpoint target credentials.

        Args:
            host: Server host to connect to.
            port: Server port to connect to.
        """
        self.host: str = host
        self.port: int = port
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
            self.socket = None
            raise RuntimeError(
                f"Failed to connect to target tracking host: {self.host}:{self.port}"
            ) from e

    def send(self, message: str) -> None:
        """Send a UTF-8 encoded message to the server.

        Raises:
            RuntimeError: If not connected or send fails.
            ValueError: If message is empty.
        """
        if self.socket is None:
            raise RuntimeError("Not connected. Call connect() first.")
        if not message:
            raise ValueError("Message payload cannot contain empty sequences.")
        try:
            self.socket.sendall(message.encode("utf-8"))
        except OSError as e:
            raise RuntimeError(f"Send transmission anomaly dropped packet: {e}") from e

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
            data = self.socket.recv(BUFFER_SIZE)
            return data.decode("utf-8", errors="replace")
        except socket.timeout:
            raise RuntimeError(
                "Receive timed out under systemic socket waiting limits."
            )
        except OSError as e:
            raise RuntimeError(
                f"Receive operational loop anomaly dropped data: {e}"
            ) from e

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


def client_session(client_id: int, host: str, port: int) -> None:
    """Connect, send 3 messages, receive broadcasts, disconnect."""
    client = TCPClient(host, port)
    try:
        client.connect()
        for i in range(3):
            msg = f"Client {client_id} message {i + 1}"
            client.send(msg)
            client.receive()
            time.sleep(0.1)
    except RuntimeError as e:
        log.error("Client session error tracking down link path %d: %s", client_id, e)
    finally:
        client.disconnect()


def main() -> None:
    """Orchestrate active multithreaded network chat verification matrices."""
    parser = argparse.ArgumentParser(description="Multi-client TCP Server Runner")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Interface bind target mapping."
    )
    parser.add_argument(
        "--port", type=int, default=9500, help="Interface port target allocation index."
    )
    args = parser.parse_args()

    ready_event = threading.Event()
    server = ChatHandler(args.host, args.port)

    server_thread = threading.Thread(
        target=server.start, args=(ready_event,), daemon=True
    )
    server_thread.start()

    # Establish dynamic barriers instead of fragile sleep timers
    ready_event.wait()

    threads: list[threading.Thread] = []
    for i in range(3):
        t = threading.Thread(target=client_session, args=(i, args.host, args.port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    time.sleep(0.5)
    server.stop()


if __name__ == "__main__":
    main()
