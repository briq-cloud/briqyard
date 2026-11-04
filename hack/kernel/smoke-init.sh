#!/bin/sh
# PID 1 of the smoke's guest (smoke.sh): prints what the kernel and its modules do.
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
release=$(uname -r)
echo "SMOKE kernel=$release"
if [ -e /dev/kvm ]; then echo "SMOKE kvm_dev=present"; else echo "SMOKE kvm_dev=absent"; fi
echo "SMOKE vmx_svm_cpus=$(grep -c -E 'vmx|svm' /proc/cpuinfo)"
echo "SMOKE kvm_dmesg=$(dmesg | grep -i -E 'kvm|vmx|svm' | tr '\n' '|')"

mkdir -p "/lib/modules/$release"
# The second drive here (/dev/vdb); a machine has more drives, so its modules drive is /dev/vdd.
if mount -t ext4 -o ro /dev/vdb "/lib/modules/$release"; then echo "SMOKE modules_mount=ok"; else echo "SMOKE modules_mount=failed"; fi
# Through the drive's modules.dep, as the sandbox image does.
if modprobe zfs; then
  if [ -d /sys/module/zfs ]; then echo "SMOKE zfs=loaded"; else echo "SMOKE zfs=missing"; fi
  echo "SMOKE zfs_version=$(cat /sys/module/zfs/version)"
else
  echo "SMOKE zfs=failed"
  dmesg | tail -n 20
fi
# Built in, br_netfilter makes this file exist from boot; as a module (not loaded) it is absent.
if [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]; then echo "SMOKE br_netfilter=builtin"; else echo "SMOKE br_netfilter=module"; fi
echo "SMOKE modules=$(cut -d: -f1 /proc/modules | tr '\n' ' ')"

if command -v nft >/dev/null; then
  cat > /tmp/smoke.nft <<'NFT'
table inet smoke {
	set blocked {
		type ipv4_addr . inet_service
	}
	set dropped {
		type ipv4_addr
		counter
	}
	limit l1 {
		rate 100/second
	}
	map conn {
		type ipv4_addr : limit
		elements = { 10.0.0.2 : "l1" }
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
		ip saddr . tcp dport @blocked ip saddr @dropped reject with tcp reset
		ct state new limit name ip saddr map @conn ip saddr @dropped drop
		fib saddr . iif oif missing drop
		ct state established,related accept
	}
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr 10.0.0.0/8 oifname "eth0" masquerade
	}
}
table bridge smoke {
	set pins {
		type ifname . ipv4_addr
	}
	chain via {
		arp saddr ip 10.0.0.9 meta ibrname "br0" drop
		drop
	}
	chain prerouting {
		type filter hook prerouting priority -200; policy drop;
		iifname . ip saddr @pins accept
		iifname . arp saddr ip @pins accept
		arp saddr ip 10.0.0.9 jump via
	}
}
NFT
  if nft -f /tmp/smoke.nft 2>/tmp/nft.err; then echo "SMOKE nft=ok"; else echo "SMOKE nft=failed $(tr '\n' ' ' </tmp/nft.err)"; fi
else
  echo "SMOKE nft=absent"
fi
echo "SMOKE done"
reboot -f
