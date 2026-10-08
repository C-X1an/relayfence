#!/usr/bin/env python3
"""Owned namespace peers and packet counters; never retain packet/payload bytes."""
import argparse
import collections
import json
import os
import selectors
import socket
import struct
import time

WORKLOAD = {'10.203.0.2', 'fd00:203::2'}
GATEWAY = {'93.184.216.33', 'fd00:204::1'}


def bucket(address, transport):
    source = 'workload' if address in WORKLOAD else ('gateway' if address in GATEWAY else 'other')
    return f'{source}.ipv{6 if ":" in address else 4}.{transport}'


class Fixture:
    def __init__(self, role, control):
        self.role, self.phase = role, 'readiness'
        self.selector = selectors.DefaultSelector()
        self.counts = collections.defaultdict(collections.Counter)
        self.udp_enabled = True
        self.tcp_port = 9000 if role == 'target' else 8444
        self.packet = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
        self.packet.bind(('eth0' if role == 'target' else 'down0', 0))
        self.register(self.packet, 'packet')
        for family, address in [(socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')]:
            for kind, port in [('tcp', self.tcp_port), ('dns', 53), ('udp', 9001)]:
                s = socket.socket(family, socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind((address, port))
                if kind == 'tcp':
                    s.listen(32)
                self.register(s, kind)
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control.bind(control)
        os.chmod(control, 0o600)
        self.control.listen(4)
        self.register(self.control, 'control')

    def register(self, s, kind, key=None):
        s.setblocking(False)
        self.selector.register(s, selectors.EVENT_READ, (kind, key))

    def packet_count(self):
        data, peer = self.packet.recvfrom(65535)
        if peer[2] == socket.PACKET_OUTGOING:
            return
        # SOCK_DGRAM strips link headers. Count owned TCP/UDP services only;
        # neighbor discovery and authenticated gateway traffic are separate paths.
        if data[0] >> 4 == 4:
            offset, protocol = (data[0] & 15) * 4, data[9]
            source = socket.inet_ntop(socket.AF_INET, data[12:16])
        elif data[0] >> 4 == 6:
            offset, protocol = 40, data[6]
            source = socket.inet_ntop(socket.AF_INET6, data[8:24])
        else:
            return
        if protocol not in (6, 17) or len(data) < offset + 4:
            return
        port = struct.unpack('!H', data[offset + 2:offset + 4])[0]
        kind = 'tcp' if protocol == 6 and port == self.tcp_port else (
            'dns' if protocol == 17 and port == 53 else ('udp' if protocol == 17 and port == 9001 else None))
        if kind:
            self.counts[bucket(source, kind)]['packets'] += 1

    def process(self, event):
        s = event.fileobj
        kind, key = event.data
        if kind == 'packet':
            self.packet_count()
        elif kind == 'tcp':
            c, peer = s.accept()
            key = bucket(peer[0], 'tcp')
            self.counts[key]['accepts'] += 1
            self.register(c, 'connection', key)
        elif kind == 'connection':
            data = s.recv(4096)
            if not data:
                self.selector.unregister(s)
                s.close()
            else:
                self.counts[key]['bytes'] += len(data)
                # Tiny synthetic echoes only; a failed fixture write invalidates the run.
                s.settimeout(.5)
                s.sendall(data)
                s.setblocking(False)
        elif kind in ('udp', 'dns'):
            data, peer = s.recvfrom(1024)
            self.counts[bucket(peer[0], kind)]['datagrams'] += 1
            if not self.udp_enabled:
                return
            if kind == 'udp':
                s.sendto(data, peer)
            else:
                offset = 12
                while data[offset]:
                    size = data[offset]
                    if size > 63:
                        raise ValueError('invalid fixture DNS label')
                    offset += size + 1
                end = offset + 5
                qtype, qclass = struct.unpack('!HH', data[offset + 1:end])
                answer = b''
                if qtype == 1 and qclass == 1:
                    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton('93.184.216.34')
                header = data[:2] + struct.pack('!HHHHH', 0x8180, 1, int(bool(answer)), 0, 0)
                s.sendto(header + data[12:end] + answer, peer)

    def drain(self):
        start = last = time.monotonic()
        while time.monotonic() - start < 3:
            events = [e for e, _ in self.selector.select(.05) if e.data[0] != 'control']
            for event in events:
                self.process(event)
            now = time.monotonic()
            if events:
                last = now
            if now - start >= .5 and now - last >= .25:
                # PACKET_STATISTICS resets on read. Any kernel observer loss is fatal.
                received, dropped = struct.unpack('II', self.packet.getsockopt(263, 6, 8))
                if dropped:
                    raise AssertionError(f'packet observer dropped {dropped} packets')
                return {'quiet_ms': round((now - last) * 1000), 'observed_since_barrier': received, 'drops': dropped}
        raise AssertionError('receiver did not reach bounded quiet/drain barrier')

    def run(self):
        print(json.dumps({'ready': self.role, 'observer': 'AF_PACKET', 'services': ['ipv4/ipv6 TCP', 'UDP', 'DNS']}), flush=True)
        while True:
            for event, _ in sorted(self.selector.select(3), key=lambda pair: pair[0].data[0] == 'control'):
                if event.data[0] != 'control':
                    self.process(event)
                    continue
                c, _ = self.control.accept()
                with c:
                    c.settimeout(4)
                    request = b''
                    while not request.endswith(b'\n'):
                        part = c.recv(1024)
                        if not part or len(request) + len(part) > 4096:
                            raise ValueError('invalid control request')
                        request += part
                    command = json.loads(request)
                    barrier = self.drain()
                    if command['action'] == 'begin':
                        self.phase = command['phase']
                        self.counts.clear()
                    elif command['action'] == 'udp':
                        self.udp_enabled = command['enabled']
                    result = {'role': self.role, 'phase': self.phase, 'barrier': barrier,
                              'udp_enabled': self.udp_enabled, 'counts': dict(self.counts)}
                    c.sendall(json.dumps(result, sort_keys=True).encode() + b'\n')


def control(args):
    request = {'action': args.action, 'phase': args.phase, 'enabled': args.enabled == 'yes'}
    deadline = time.monotonic() + 6
    while True:
        try:
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.settimeout(5)
            c.connect(args.control)
            break
        except (FileNotFoundError, ConnectionRefusedError):
            c.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(.1)
    with c:
        c.sendall(json.dumps(request).encode() + b'\n')
        reply = b''
        while not reply.endswith(b'\n'):
            part = c.recv(4096)
            assert part, 'receiver died before barrier acknowledgement'
            reply += part
    result = json.loads(reply)
    print(json.dumps(result, sort_keys=True), flush=True)
    if args.action != 'verify':
        return
    assert result['phase'] == args.phase, 'wrong receiver phase'
    counts = result['counts']
    direct = any(sum(value.values()) for key, value in counts.items() if key.startswith('workload.'))
    if args.expected == 'guarded':
        assert not direct, 'direct workload packets reached receiver'
        if result['role'] == 'target':
            for kind, fields in [('tcp', ('packets', 'accepts', 'bytes')), ('dns', ('packets', 'datagrams'))]:
                for field in fields:
                    assert counts.get('gateway.ipv4.' + kind, {}).get(field, 0) > 0, ('missing allowed gateway effect', kind, field)
    elif args.expected == 'permissive':
        for version in (4, 6):
            for kind, fields in [('tcp', ('packets', 'accepts', 'bytes')), ('udp', ('packets', 'datagrams')), ('dns', ('packets', 'datagrams'))]:
                for field in fields:
                    assert counts.get(f'workload.ipv{version}.{kind}', {}).get(field, 0) > 0, ('dead positive control', version, kind, field)
    elif args.expected == 'one-way':
        for version in (4, 6):
            assert counts.get(f'workload.ipv{version}.tcp', {}).get('packets', 0) > 0, 'missing leaked SYN observation'
            assert counts.get(f'workload.ipv{version}.tcp', {}).get('accepts', 0) == 0, 'one-way TCP handshake unexpectedly completed'
            for kind in ('udp', 'dns'):
                for field in ('packets', 'datagrams'):
                    assert counts.get(f'workload.ipv{version}.{kind}', {}).get(field, 0) > 0, 'missing one-way UDP/DNS receiver effect'
        try:
            assert not direct, 'direct workload packets reached receiver'
        except AssertionError as exc:
            print(json.dumps({'mutant': 'one-way', 'rejected': str(exc)}))
        else:
            raise AssertionError('one-way escape mutant survived receiver assertions')
    elif args.expected == 'dead-udp':
        assert not result['udp_enabled'], 'UDP mutant not installed'
        for kind, fields in [('tcp', ('packets', 'accepts', 'bytes')), ('udp', ('packets', 'datagrams'))]:
            for field in fields:
                assert counts.get('workload.ipv4.' + kind, {}).get(field, 0) > 0, ('missing dead-UDP mutant receiver effect', kind, field)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['serve', 'begin', 'verify', 'udp'])
    p.add_argument('--role', choices=['target', 'management'])
    p.add_argument('--control', required=True)
    p.add_argument('--phase', default='readiness')
    p.add_argument('--expected', choices=['guarded', 'permissive', 'one-way', 'dead-udp'])
    p.add_argument('--enabled', choices=['yes', 'no'], default='yes')
    args = p.parse_args()
    if args.action == 'serve':
        Fixture(args.role, args.control).run()
    else:
        control(args)
