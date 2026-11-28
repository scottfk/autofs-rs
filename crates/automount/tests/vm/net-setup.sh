# 20261127 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261127 - Run 127.0.0.1 lines in the case's namespace; FAKE_NFSD_DIR for ypserv maps - Claude - scottfk
#
# net-setup.sh - sourced by run-case.sh when a case has a "net" file: the
# case runs in a network namespace of its own (10.77.0.1/24 on vh), joined by
# a veth pair to a second one holding the fake servers (tests/... fake-nfsd)
# on the addresses the file names: 10.77.0.x on the link (subnet), others on
# its loopback behind routes (10.78.x: the same class A network; others: a
# different network). 10.77.0.2 is always there, as the router. Lines for
# 127.0.0.1 are servers in the case's own namespace (a local ypbind).
ip link set lo up
setsid -f unshare -n sh -c "echo \$\$ > $C/ovl/srvns.pid; exec sleep 100000"
n=0
while [ ! -s "$C/ovl/srvns.pid" ] && [ $n -lt 50 ]; do n=$((n+1)); sleep 0.1; done
SNS=$(cat "$C/ovl/srvns.pid")
ip link add vh type veth peer name vs netns "$SNS"
ip addr add 10.77.0.1/24 dev vh
ip link set vh up
nsenter -t "$SNS" -n ip link set lo up
nsenter -t "$SNS" -n ip link set vs up
nsenter -t "$SNS" -n ip addr add 10.77.0.2/24 dev vs
awk '$1 == "127.0.0.1"' "$C/net" > "$C/ovl/net.local"
awk '$1 != "127.0.0.1"' "$C/net" > "$C/ovl/net.srv"
export FAKE_NFSD_DIR="$C"
for a in $(awk '{print $1}' "$C/ovl/net.srv" | sort -u); do
	case $a in
	10.77.0.2) ;;
	10.77.0.*) nsenter -t "$SNS" -n ip addr add "$a/24" dev vs ;;
	*) nsenter -t "$SNS" -n ip addr add "$a/32" dev lo ;;
	esac
done
nsenter -t "$SNS" -n ip route add default via 10.77.0.1
ip route add 10.78.0.0/16 via 10.77.0.2
ip route add 192.0.2.0/24 via 10.77.0.2
nsenter -t "$SNS" -n setsid -f "$B/r/fake-nfsd" "$C/ovl/net.srv" "$C/ovl/nfsd.ready"
[ -s "$C/ovl/net.local" ] && setsid -f "$B/r/fake-nfsd" "$C/ovl/net.local" "$C/ovl/local.ready"
n=0
while [ ! -s "$C/ovl/nfsd.ready" ] && [ $n -lt 50 ]; do n=$((n+1)); sleep 0.1; done
[ -s "$C/ovl/nfsd.ready" ] || echo "fake-nfsd did not start" >> "$C/out/steps"
if [ -s "$C/ovl/net.local" ]; then
	n=0
	while [ ! -s "$C/ovl/local.ready" ] && [ $n -lt 50 ]; do n=$((n+1)); sleep 0.1; done
	[ -s "$C/ovl/local.ready" ] || echo "local fake-nfsd did not start" >> "$C/out/steps"
fi
net_down() {
	kill "$(cat "$C/ovl/nfsd.ready")" "$SNS" 2>/dev/null || true
	[ -s "$C/ovl/local.ready" ] && kill "$(cat "$C/ovl/local.ready")" 2>/dev/null || true
}
