#!/usr/bin/env python3
"""Capability-free workload probes; receiver counters decide zero-packet denial."""
import argparse
import json
import os
import socket
import ssl
import struct
from pathlib import Path


def tcp(address, port, allowed):
    succeeded = False
    try:
        with socket.create_connection((address, port), timeout=.5) as c:
            c.sendall(b'control')
            body = b''
            while len(body) < 7:
                part = c.recv(7 - len(body))
                if not part:
                    break
                body += part
            succeeded = body == b'control'
    except OSError:
        pass
    assert succeeded == allowed, (address, port, 'expected', allowed, 'observed', succeeded)


def udp(address, dns, allowed):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    query = struct.pack('!HHHHHH', 123, 0x100, 1, 0, 0, 0) + b'\x04echo\x04test\x00' + struct.pack('!HH', 1, 1)
    payload = query if dns else b'udp-control'
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(.5)
        succeeded = False
        try:
            # Connected UDP also enforces that the reply comes from the named peer.
            s.connect((address, 53 if dns else 9001))
            s.send(payload)
            response = s.recv(1024)
            if dns:
                expected = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton('93.184.216.34')
                succeeded = response == expected
            else:
                succeeded = response == payload
        except OSError:
            pass
        assert succeeded == allowed, ('DNS' if dns else 'UDP', address, 'expected', allowed, 'observed', succeeded)


def proxy(args):
    context = ssl.create_default_context(cafile=str(Path(args.cert_dir) / 'ca.crt'))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(Path(args.cert_dir) / 'client.crt'), str(Path(args.cert_dir) / 'client.key'))
    with socket.create_connection(('10.203.0.1', 8443), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname='gateway.test') as c:
            c.sendall(b'CONNECT echo.test:9000 HTTP/1.1\r\nHost: echo.test:9000\r\n\r\n')
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                part = c.recv(1)
                assert part, 'EOF before CONNECT response'
                header += part
                assert len(header) <= 8192
            assert header.startswith(b'HTTP/1.1 200 '), header
            payload = b'contained-proxy-echo'
            c.sendall(payload)
            body = b''
            while len(body) < len(payload):
                part = c.recv(len(payload) - len(body))
                assert part, 'EOF before complete echo'
                body += part
            assert body == payload


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['guarded', 'permissive', 'one-way', 'dead-udp'], required=True)
    p.add_argument('--cert-dir', required=True)
    p.add_argument('--admin', required=True)
    args = p.parse_args()
    status = dict(line.strip().split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    assert os.getuid() == 61102
    for key in ['CapEff', 'CapPrm', 'CapBnd', 'CapAmb']:
        assert int(status[key].strip(), 16) == 0, (key, status[key])
    assert status['NoNewPrivs'].strip() == '1'
    if args.mode == 'guarded':
        proxy(args)
    if args.mode == 'dead-udp':
        tcp('10.203.0.1', 8444, True)
        try:
            udp('10.203.0.1', False, True)
        except AssertionError as exc:
            assert exc.args == (('UDP', '10.203.0.1', 'expected', True, 'observed', False),), 'unexpected mutant failure'
            print(json.dumps({'mutant': 'dead-udp', 'rejected': str(exc)}))
            return
        raise AssertionError('dead UDP responder survived positive controls')
    endpoints = [('10.203.0.1', 8444), ('fd00:203::1', 8444)]
    if args.mode != 'one-way':
        endpoints += [('93.184.216.34', 9000), ('fd00:204::2', 9000)]
    for address, port in endpoints:
        tcp(address, port, args.mode == 'permissive')
        for dns in (False, True):
            udp(address, dns, args.mode == 'permissive')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        try:
            s.connect(args.admin)
        except PermissionError:
            pass
        else:
            raise AssertionError('workload reached private Unix admin')
    print(json.dumps({'phase': args.mode, 'client_assertions': 'PASS', 'capabilities': 0,
                      'meaning': 'receiver barrier assertions are required to establish containment'}))


if __name__ == '__main__':
    main()
