#!/usr/bin/env bash
# Step 3 smoke test: start control plane, inject traffic, capture
# dashboard + per-node log, verify clean shutdown.
set -u
cd "$(dirname "$0")/.."

rm -f /tmp/cp.log
python3 control_plane/main.py > /tmp/cp.log 2>&1 &
CP=$!

# Wait for nodes to bind and first heartbeat tick to arrive.
sleep 4

echo "=== injecting test packets ==="
python3 scripts/send_packet.py --port 8001 --dst 1 --id 100 --src 99
python3 scripts/send_packet.py --port 8001 --dst 7 --id 200 --src 99
python3 scripts/send_packet.py --port 8008 --dst 2 --id 300 --src 99
python3 scripts/send_packet.py --port 8001 --dst 99 --id 400 --src 99

# Wait for at least one more dashboard render after the counters move.
sleep 3

echo "=== SIGINT control plane ==="
kill -INT "$CP"
wait "$CP"
echo "control plane exit: $?"

echo
echo "=== tail of control plane stdout (most recent dashboard) ==="
tail -25 /tmp/cp.log

echo
echo "=== /tmp/netshield/node-1.log (head) ==="
head -20 /tmp/netshield/node-1.log

echo
echo "=== /tmp/netshield/node-3.log (FORWARD/DELIVER lines only) ==="
grep -E 'FORWARD|DELIVER|listening' /tmp/netshield/node-3.log

echo
echo "=== port cleanup ==="
ss -ulnp 2>/dev/null | grep -E ":(800[1-8]|9000)" && echo "STILL_BOUND" || echo "all 9 ports released"
