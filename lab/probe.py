"""Small, bounded clients for the lab fixtures. Invoked inside source namespaces."""

import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import sys
from functools import lru_cache

from lab.guest import SECRETS, guard
from lab.model import INTERNAL, TEST_WAN, load

TIMEOUT = 0.75


def destination(value):
    ip = ipaddress.ip_address(value)
    if not (ip in INTERNAL or ip in TEST_WAN):
        raise ValueError("Probe destination is outside the laboratory")
    return str(ip)


def read_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        piece = sock.recv(count - len(data))
        if not piece:
            raise OSError("Truncated response")
        data.extend(piece)
    return bytes(data)


def query_name(packet, offset=12):
    labels = []
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            return ".".join(labels), offset
        if size > 63 or offset + size > len(packet):
            break
        try:
            labels.append(packet[offset:offset + size].decode("ascii").lower())
        except UnicodeDecodeError:
            break
        offset += size
    raise ValueError("Invalid DNS question")


def dns(ip, port, protocol, label):
    ident = secrets.randbelow(65536)
    encoded = b"".join(bytes((len(part),)) + part.encode("ascii") for part in label.split("."))
    request = struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + encoded + b"\x00\x00\x01\x00\x01"
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        if protocol == "tcp":
            sock.sendall(struct.pack("!H", len(request)) + request)
            response = read_exact(sock, struct.unpack("!H", read_exact(sock, 2))[0])
        else:
            sock.send(request)
            response = sock.recv(4096)
    response_id, flags, _, answers, _, _ = struct.unpack_from("!6H", response)
    if response_id != ident or not (flags & 0x8000):
        raise ValueError("Unexpected DNS response")
    _, offset = query_name(response)
    offset += 4
    records = []
    for _ in range(answers):
        if response[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            _, offset = query_name(response, offset)
        kind, rr_class, _, length = struct.unpack_from("!HHIH", response, offset)
        offset += 10
        if kind == 1 and rr_class == 1 and length == 4:
            records.append(socket.inet_ntoa(response[offset:offset + length]))
        offset += length
    return {"result": "dns", "rcode": flags & 0xF, "recursion_available": bool(flags & 0x0080), "answers": records}


@lru_cache(maxsize=8)
def client_context(identity):
    context = ssl.create_default_context(cafile=SECRETS / "services.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if identity != "-":
        context.load_cert_chain(SECRETS / f"{identity}.pem", SECRETS / f"{identity}.key")
    return context


def request(ip, port, service, identity, path, hostname_override=None):
    hostname = hostname_override or service.get("host", ip)
    context = client_context(identity) if service["kind"] in {"mtls", "public"} else None
    with socket.create_connection((ip, port), 1.2) as stream:
        stream.settimeout(2)
        if context:
            with context.wrap_socket(stream, server_hostname=hostname) as tls:
                return read_http(tls, hostname, path)
        return read_http(stream, hostname, path)


def read_http(stream, hostname, path):
    stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode("ascii"))
    response = http.client.HTTPResponse(stream)
    response.begin()
    body = response.read(100_001)
    if len(body) > 100_000:
        raise ValueError("Fixture response exceeded the probe envelope")
    return {"result": "http", "status": response.status, "kind": response.getheader("Content-Type"), "body": body.decode()}


def perform(policy, protocol, ip, port, *details):
    guard()
    ip = destination(ip)
    port = int(port)
    try:
        if protocol == "http":
            name, identity, path, *override = details
            payload = request(ip, port, policy["services"][name], identity, path, override[0] if override else None)
        elif protocol == "dns":
            payload = dns(ip, port, *details)
        elif protocol == "tcp":
            origin = (destination(details[0]), 0) if details else None
            with socket.create_connection((ip, port), TIMEOUT, source_address=origin):
                payload = {"result": "connected"}
        elif protocol == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect((ip, port))
                sock.send(b"lab-only")
                payload = {"result": "reply", "bytes": len(sock.recv(128))}
        else:
            raise ValueError("Unknown test protocol")
    except TimeoutError:
        payload = {"result": "timeout"}
    except ssl.SSLCertVerificationError as error:
        payload = {"result": "certificate_error", "reason": error.verify_message}
    except (ssl.SSLError, http.client.RemoteDisconnected, ConnectionResetError) as error:
        payload = {"result": "rejected", "reason": getattr(error, "reason", None) or type(error).__name__}
    except OSError as error:
        payload = {"result": "os_error", "errno": error.errno}
    return payload


def main():
    print(json.dumps(perform(load(), *sys.argv[1:]), sort_keys=True))


if __name__ == "__main__":
    main()
