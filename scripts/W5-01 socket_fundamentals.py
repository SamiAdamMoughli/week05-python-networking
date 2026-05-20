import threading

import socket


# TCP
def run_tcp_server(host, port, event):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        event.set()
        conn, addr = s.accept()
        with conn:
            while data := conn.recv(1024):
                conn.sendall(data)


def run_tcp_client(host, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message.encode("utf-8"))
        print(s.recv(1024))


def demo_tcp(host, port, message="hello TCP"):
    event = threading.Event()
    thread = threading.Thread(
        target=run_tcp_server, args=(host, port, event), daemon=True
    )
    thread.start()
    event.wait()
    run_tcp_client(host, port, message)


# UDP
def run_udp_server(host, port, event):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        event.set()
        while True:
            data, addr = s.recvfrom(4096)
            s.sendto(data, addr)


def run_udp_client(host, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(message.encode("utf-8"), (host, port))
        print(s.recvfrom(4096))


def demo_udp(host, port, message="hello UDP"):
    event = threading.Event()
    thread = threading.Thread(
        target=run_udp_server, args=(host, port, event), daemon=True
    )
    thread.start()
    event.wait()
    run_udp_client(host, port, message)


# Socket Option Demo
# SO_REUSEADDR is needed because operating systems hold recently closed sockets in TIME_WAIT to prevent delayedpackets from being misdelivered, which can block a server from rebinding the same IP:port immediately after shutdown;setting SO_REUSEADDR lets the server rebind right away (useful during restarts, rapid deployments, or testing) whileaccepting the responsibility to handle potential late/delivered packets and platform-specific semantics.
def demo_socket_options(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"listening (no reuse) on {host}:{port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.connect((host, 19999))
        except TimeoutError:
            print("Connection timed out!")
        except ConnectionRefusedError:
            print("Connection refused!")

    # Without settimeout(), connect() blocks indefinitely on a dead host.
    # The process hangs with no way to recover short of killing it.
    # Always set a timeout on client sockets before connecting.

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        result = s.connect_ex((host, 19999))
        if result == 0:
            print("port open")
        else:
            print(f"port closed or filtered (errno {result})")


# Hostname resolution
def demo_resolution(host, port):
    ipv4 = socket.gethostbyname(host)
    info = socket.getaddrinfo(host, port)
    name_info = socket.getnameinfo((ipv4, port), 0)
    print(f"IPv4: {ipv4}")
    print(f"AddrInfo: {info}")
    print(f"NameInfo: {name_info}")


if __name__ == "__main__":
    demo_tcp("127.0.0.1", 9100)
    demo_udp("127.0.0.1", 9200)
    demo_socket_options("127.0.0.1", 9300)
    demo_resolution("google.com", 443)
