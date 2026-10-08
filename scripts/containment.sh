#!/bin/sh
# Only modifies three newly-created namespaces and their per-namespace resolver.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
python3 - <<'PY'
import os,shutil,sys
from pathlib import Path
if sys.platform!='linux':print('BLOCKED HA-002: Linux required');sys.exit(77)
status=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
caps=int(status['CapEff'].strip(),16)
if os.geteuid()!=0 or not (caps&(1<<12) and caps&(1<<21)):
 print('BLOCKED HA-002: dedicated Linux host with CAP_NET_ADMIN and CAP_SYS_ADMIN required; host policy is not changed');sys.exit(77)
for tool in ['ip','nft','setpriv','openssl','python3','go','sysctl']:
 if not shutil.which(tool):print('BLOCKED HA-002: missing '+tool);sys.exit(77)
PY
[ "${RELAYFENCE_DISPOSABLE_HOST:-}" = 1 ] || { echo 'BLOCKED HA-002: run only on an authorized disposable host; set RELAYFENCE_DISPOSABLE_HOST=1 there'; exit 77; }
make build
suffix=$(python3 -c 'import uuid;print(uuid.uuid4().hex[:7])')
w="rfw$suffix";g="rfg$suffix";t="rft$suffix"
tmp=$(mktemp -d)
cleanup(){
 set +e
 for log in target management gateway; do
  if [ -f "$tmp/$log.log" ]; then
   printf '%s\n' "fixture diagnostic: $log"
   cat "$tmp/$log.log"
  fi
 done
 for ns in "$w" "$g" "$t"; do
  pids=$(ip netns pids "$ns" 2>/dev/null)
  [ -z "$pids" ] || kill $pids 2>/dev/null
  ip netns del "$ns" 2>/dev/null
 done
 rm -rf "/etc/netns/$g" "$tmp"
}
trap cleanup EXIT HUP INT TERM
chmod 711 "$tmp"
mkdir -p "$tmp/server" "$tmp/client" "$tmp/state" "$tmp/tools"
chmod 700 "$tmp/server" "$tmp/client" "$tmp/state"
cp bin/relayfence "$tmp/tools/relayfence"
cp infra/containment/fixture.py infra/containment/client.py "$tmp/tools/"
chmod 755 "$tmp/tools" "$tmp/tools/relayfence"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/ca.key" 2>/dev/null
openssl req -new -x509 -key "$tmp/ca.key" -out "$tmp/ca.crt" -days 1 -subj '/CN=RelayFence disposable containment CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
for role in server client; do
 openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/$role/$role.key" 2>/dev/null
 openssl req -new -key "$tmp/$role/$role.key" -out "$tmp/$role.csr" -subj "/CN=$role" 2>/dev/null
 if [ "$role" = server ]; then
  printf '%s\n' 'subjectAltName=DNS:gateway.test' 'extendedKeyUsage=serverAuth' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' > "$tmp/ext"
 else
  printf '%s\n' 'subjectAltName=URI:urn:relayfence:workload:containment' 'extendedKeyUsage=clientAuth' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' > "$tmp/ext"
 fi
 openssl x509 -req -in "$tmp/$role.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial -out "$tmp/$role/$role.crt" -days 1 -extfile "$tmp/ext" 2>/dev/null
 cp "$tmp/ca.crt" "$tmp/$role/ca.crt"
 chmod 600 "$tmp/$role/"*
done
cat > "$tmp/state/policy.json" <<'JSON'
{"schema_version":1,"revision":1,"global_max_active":16,"rules":[{"identity":"urn:relayfence:workload:containment","destinations":["echo.test:9000"],"max_active":4,"max_bytes":1048576,"max_duration_ms":10000,"idle_timeout_ms":3000}]}
JSON
chmod 600 "$tmp/state/policy.json"
chown -R 61101:61101 "$tmp/server" "$tmp/state"
chown -R 61102:61102 "$tmp/client"
for ns in "$w" "$g" "$t"; do ip netns add "$ns";ip -n "$ns" link set lo up;done
# Forwarding controls belong to the disposable gateway namespace only.
ip netns exec "$g" sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
ip link add "a$suffix" type veth peer name "b$suffix"
ip link set "a$suffix" netns "$w";ip link set "b$suffix" netns "$g"
ip -n "$w" link set "a$suffix" name eth0;ip -n "$g" link set "b$suffix" name down0
ip link add "c$suffix" type veth peer name "d$suffix"
ip link set "c$suffix" netns "$g";ip link set "d$suffix" netns "$t"
ip -n "$g" link set "c$suffix" name up0;ip -n "$t" link set "d$suffix" name eth0
ip -n "$w" addr add 10.203.0.2/30 dev eth0;ip -n "$w" addr add fd00:203::2/64 dev eth0 nodad
ip -n "$g" addr add 10.203.0.1/30 dev down0;ip -n "$g" addr add fd00:203::1/64 dev down0 nodad
# Public-shaped test IPs are confined to an isolated veth; no Internet route exists.
ip -n "$g" addr add 93.184.216.33/30 dev up0;ip -n "$g" addr add fd00:204::1/64 dev up0 nodad
ip -n "$t" addr add 93.184.216.34/30 dev eth0;ip -n "$t" addr add fd00:204::2/64 dev eth0 nodad
ip -n "$w" link set eth0 up;ip -n "$g" link set down0 up;ip -n "$g" link set up0 up;ip -n "$t" link set eth0 up
mkdir -p "/etc/netns/$g"
printf '%s\n' 'nameserver 93.184.216.34' 'options timeout:1 attempts:1' > "/etc/netns/$g/resolv.conf"
cat > "$tmp/gateway.nft" <<'NFT'
table inet relayfence_gateway {
 chain forward { type filter hook forward priority 0; policy drop; }
}
NFT
ip netns exec "$g" nft -f "$tmp/gateway.nft"
cat > "$tmp/workload.nft" <<'NFT'
table inet relayfence_workload {
 chain output {
  type filter hook output priority 0; policy drop;
  oifname "lo" accept
  ct state established,related accept
  ip daddr 10.203.0.1 tcp dport 8443 accept
  ip6 nexthdr ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
 }
 chain input {
  type filter hook input priority 0; policy drop;
  iifname "lo" accept
  ct state established,related accept
  ip6 nexthdr ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
 }
}
NFT
ip netns exec "$w" nft -f "$tmp/workload.nft"
ip netns exec "$t" python3 "$tmp/tools/fixture.py" serve --role target --control "$tmp/target.sock" > "$tmp/target.log" 2>&1 &
ip netns exec "$g" python3 "$tmp/tools/fixture.py" serve --role management --control "$tmp/management.sock" > "$tmp/management.log" 2>&1 &
ip netns exec "$g" setpriv --reuid 61101 --regid 61101 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs env GODEBUG=netdns=go "$tmp/tools/relayfence" serve --listen 10.203.0.1:8443 --cert "$tmp/server/server.crt" --key "$tmp/server/server.key" --ca "$tmp/server/ca.crt" --policy "$tmp/state/policy.json" --audit "$tmp/state/audit.jsonl" --admin "$tmp/state/admin.sock" > "$tmp/gateway.log" 2>&1 &
# Readiness is bounded and does not assert application acceptance.
ip netns exec "$g" python3 - <<'PY'
import socket,time
for attempt in range(50):
 try:
  with socket.create_connection(('10.203.0.1',8443),.2):pass
  with socket.create_connection(('10.203.0.1',8444),.2) as c:c.sendall(b'ok');assert c.recv(2)==b'ok'
  break
 except OSError:time.sleep(.1)
else:raise SystemExit('fixture readiness failed')
PY
run_client(){ ip netns exec "$w" setpriv --reuid 61102 --regid 61102 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs python3 "$tmp/tools/client.py" --mode "$1" --cert-dir "$tmp/client" --admin "$tmp/state/admin.sock"; }
# POSIX shell functions use explicit arguments (no bash array expansion).
receiver(){ role=$1;action=$2;shift 2;python3 "$tmp/tools/fixture.py" "$action" --control "$tmp/$role.sock" --phase "$phase" "$@"; }
begin(){ phase=$1;receiver management begin;receiver target begin; }
verify(){ receiver management verify --expected "$1";receiver target verify --expected "$1"; }
begin guarded
run_client guarded
verify guarded

# Test the packet observer with one-way TCP SYN / UDP leaks and blocked replies.
# A response-only denial still passes here, but the receiver MUST reject it.
begin one-way-mutant
ip netns exec "$w" nft -f - <<'NFT'
insert rule inet relayfence_workload output ip daddr 10.203.0.1 tcp dport 8444 accept
insert rule inet relayfence_workload output ip6 daddr fd00:203::1 tcp dport 8444 accept
insert rule inet relayfence_workload output ip daddr 10.203.0.1 udp dport { 53, 9001 } accept
insert rule inet relayfence_workload output ip6 daddr fd00:203::1 udp dport { 53, 9001 } accept
insert rule inet relayfence_workload input tcp sport 8444 drop
insert rule inet relayfence_workload input udp sport { 53, 9001 } drop
NFT
run_client one-way
receiver management verify --expected one-way
ip netns exec "$w" nft delete table inet relayfence_workload
ip netns exec "$w" nft -f "$tmp/workload.nft"

# Remove every control needed to make each owned endpoint reachable, all inside
# the three namespaces. No default route or external Internet target is added.
ip netns exec "$w" nft delete table inet relayfence_workload
ip netns exec "$g" nft delete table inet relayfence_gateway
ip netns exec "$g" sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip -n "$w" route add 93.184.216.32/30 via 10.203.0.1
ip -n "$w" -6 route add fd00:204::/64 via fd00:203::1
ip -n "$t" route add 10.203.0.0/30 via 93.184.216.33
ip -n "$t" -6 route add fd00:203::/64 via fd00:204::1

# A dead UDP responder must invalidate the positive controls, never pass denial.
begin dead-udp-mutant
receiver management udp --enabled no
run_client dead-udp
receiver management verify --expected dead-udp
receiver management udp --enabled yes
begin removed-control
run_client permissive
verify permissive

# Restore the normal no-route/no-forward guarded profile and repeat all proofs.
ip -n "$w" route del 93.184.216.32/30 via 10.203.0.1
ip -n "$w" -6 route del fd00:204::/64 via fd00:203::1
ip -n "$t" route del 10.203.0.0/30 via 93.184.216.33
ip -n "$t" -6 route del fd00:203::/64 via fd00:204::1
ip netns exec "$g" sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
ip netns exec "$g" nft -f "$tmp/gateway.nft"
ip netns exec "$w" nft -f "$tmp/workload.nft"
begin restored-control
run_client guarded
verify guarded
printf '%s\n' 'PASS: real namespace zero-packet guarded/restored checks, IPv4/IPv6 TCP/UDP/DNS working controls and rejected one-way/dead-UDP mutants. No global host firewall modified.'
