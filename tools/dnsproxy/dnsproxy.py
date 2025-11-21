#!/usr/bin/env python3
# coding: utf-8

import socketserver
from io import BytesIO
import os
import socket
import struct
import time
import argparse

"""
A simple DNS proxy server supporting:
- wildcard hosts
- IPv6
- response caching

Python 3 port by ChatGPT
Original author: marlonyao <yaolei135@gmail.com>
"""


# ------------------------------------------------------------
# Utility struct-like object
# ------------------------------------------------------------
class Struct(object):
    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            setattr(self, name, value)


# ------------------------------------------------------------
# DNS Parsing
# ------------------------------------------------------------
def parse_dns_message(data: bytes):
    message = BytesIO(data)
    message.seek(4)  # skip id + flags
    c_qd, c_an, c_ns, c_ar = struct.unpack("!4H", message.read(8))

    # Parse question
    question = parse_dns_question(message)
    for _ in range(1, c_qd):  # skip extra questions
        parse_dns_question(message)

    # Parse all records
    records = []
    for _ in range(c_an + c_ns + c_ar):
        records.append(parse_dns_record(message))

    return Struct(question=question, records=records)


def read_byte(message: BytesIO):
    b = message.read(1)
    if not b:
        return 0
    return b[0]  # Python 3 → integer


def parse_domain_name(message: BytesIO):
    return ".".join(_parse_domain_labels(message))


def _parse_domain_labels(message: BytesIO):
    labels = []
    length = read_byte(message)

    while length > 0:
        if length >= 64:  # pointer (compression)
            pointer_high = length & 0x3F
            pointer_low = read_byte(message)
            offset = (pointer_high << 8) + pointer_low

            # Follow the pointer
            saved_pos = message.tell()
            temp = BytesIO(message.getvalue())
            temp.seek(offset)
            labels.extend(_parse_domain_labels(temp))
            message.seek(saved_pos)
            return labels

        else:
            labels.append(message.read(length).decode("utf-8", "ignore"))

        length = read_byte(message)

    return labels


def parse_dns_question(message: BytesIO):
    qname = parse_domain_name(message)
    qtype, qclass = struct.unpack("!HH", message.read(4))
    end_offset = message.tell()
    return Struct(name=qname, type_=qtype, class_=qclass, end_offset=end_offset)


def parse_dns_record(message: BytesIO):
    parse_domain_name(message)  # skip name
    message.seek(4, os.SEEK_CUR)  # skip type + class
    ttl_offset = message.tell()
    ttl = struct.unpack("!I", message.read(4))[0]
    rd_len = struct.unpack("!H", message.read(2))[0]
    message.seek(rd_len, os.SEEK_CUR)
    return Struct(ttl_offset=ttl_offset, ttl=ttl)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def addr_p2n(addr):
    try:
        return socket.inet_pton(socket.AF_INET, addr)
    except OSError:
        return socket.inet_pton(socket.AF_INET6, addr)


# DNS constants
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_CLASS_IN = 1


# ------------------------------------------------------------
# DNS Proxy Handler
# ------------------------------------------------------------
class DNSProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        reqdata, sock = self.request
        req = parse_dns_message(reqdata)
        q = req.question

        # Handle wildcard hosts
        if q.type_ in (DNS_TYPE_A, DNS_TYPE_AAAA) and q.class_ == DNS_CLASS_IN:
            for packed_ip, host in self.server.host_lines:
                if q.name.endswith(host):
                    rsp = self._forge_response(reqdata, q, packed_ip)
                    sock.sendto(rsp, self.client_address)
                    return

        # Cache lookup
        cache = self.server.cache
        cache_key = (q.name, q.type_, q.class_)

        if not self.server.disable_cache and cache_key in cache:
            rsp = update_ttl(reqdata, cache[cache_key])
            if rsp:
                sock.sendto(rsp, self.client_address)
                return

        # Forward request to real DNS server
        rsp = self._query_upstream(reqdata)
        if not self.server.disable_cache:
            cache[cache_key] = Struct(rspdata=rsp, cache_time=int(time.time()))

        sock.sendto(rsp, self.client_address)

    def _forge_response(self, reqdata, q, packed_ip):
        # Header: same ID + standard response
        rsp = reqdata[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        rsp += reqdata[12:q.end_offset]

        # Answer record
        rsp += b"\xc0\x0c"  # pointer to qname

        if len(packed_ip) == 4:
            rsp += b"\x00\x01"  # A
        else:
            rsp += b"\x00\x1c"  # AAAA

        rsp += b"\x00\x01\x00\x00\x07\xd0"  # class + TTL 2000

        rsp += struct.pack("!H", len(packed_ip))
        rsp += packed_ip
        return rsp

    def _query_upstream(self, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((self.server.dns_server, 53))
        sock.sendall(data)
        sock.settimeout(60)
        rsp = sock.recv(65535)
        sock.close()
        return rsp


# ------------------------------------------------------------
# TTL Updater
# ------------------------------------------------------------
def update_ttl(reqdata, cache_entry):
    rspdata, cache_time = cache_entry.rspdata, cache_entry.cache_time
    rsp = bytearray(rspdata)
    rsp[:2] = reqdata[:2]  # update ID

    now = int(time.time())
    delta = now - cache_time

    parsed = parse_dns_message(rspdata)
    for record in parsed.records:
        new_ttl = record.ttl - delta
        if new_ttl <= 0:
            return None

        rsp[record.ttl_offset:record.ttl_offset + 4] = struct.pack("!I", new_ttl)

    return bytes(rsp)


# ------------------------------------------------------------
# Load hosts wildcard rules
# ------------------------------------------------------------
def load_hosts(path):
    hostlines = []

    def wildcard(line):
        parts = line.split()
        if len(parts) < 2:
            return None
        ip, host = parts[0], parts[1]
        if not host.startswith("*"):
            return None
        try:
            packed = addr_p2n(ip)
            return (packed, host[1:])
        except Exception:
            return None

    with open(path) as f:
        for line in f:
            w = wildcard(line.strip())
            if w:
                hostlines.append(w)

    return hostlines


# ------------------------------------------------------------
# DNS Proxy Server
# ------------------------------------------------------------
class DNSProxyServer(socketserver.ThreadingUDPServer):
    def __init__(self, dns_server, disable_cache=False, host="127.0.0.1", port=53, hosts_file="/etc/hosts"):
        self.dns_server = dns_server
        self.hosts_file = hosts_file
        self.host_lines = load_hosts(hosts_file)
        self.disable_cache = disable_cache
        self.cache = {}
        super().__init__((host, port), DNSProxyHandler)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--hosts-file", default="/etc/hosts")
    parser.add_argument("-H", "--host", default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=53)
    parser.add_argument("-s", "--server", required=True)
    parser.add_argument("-C", "--no-cache", action="store_true")

    opts = parser.parse_args()

    server = DNSProxyServer(
        opts.server,
        disable_cache=opts.no_cache,
        host=opts.host,
        port=opts.port,
        hosts_file=opts.hosts_file
    )

    print(f"DNS Proxy running on {opts.host}:{opts.port} → forwarding to {opts.server}")
    server.serve_forever()


if __name__ == "__main__":
    main()