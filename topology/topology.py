import time
import random
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Link

K                = 4
N_PODS           = K
N_CORE           = (K // 2) ** 2
N_AGG_PER_POD    = K // 2
N_EDGE_PER_POD   = K // 2
N_HOSTS_PER_EDGE = K // 2

CONTROLLER_IP   = "127.0.0.1"
CONTROLLER_PORT = 6633

# ------------------------------------------------------------------
# Traffic volume constants
# ------------------------------------------------------------------
# M10 fix: BASELINE_PING_INTERVAL = "3" was used only in the banner string
# while start_baseline_traffic() hardcoded "0.5" and "3" directly, making
# the constant misleading and the banner inaccurate.  Split into two named
# constants and use them in both the functions and the banner.

# Initial burst: 150 packets at 2 pps — reaches >100 pkts in OVS flow table
# (required for the per-flow pkt_count >= 50 guard in ryu_controller to pass).
# 2 pps is safely below the 5 pps ML gate so no false positives fire.
BASELINE_BURST_INTERVAL = "0.5"   # ping -i 0.5 → 2 pps

# Continuous slow ping after burst — just enough to keep the flow alive.
# 0.33 pps is well below every ML gate (zmq MIN_PPS=20, worker pps<5).
BASELINE_CONT_INTERVAL  = "3"     # ping -i 3  → 0.33 pps

ATTACK_PKT_COUNT = 3000

_CAMPAIGNS = [
    ("h1",  "h2"),
    ("h5",  "h6"),
    ("h9",  "h10"),
    ("h13", "h14"),
]


def build_fat_tree():
    net = Mininet(
        controller=None,
        switch=OVSKernelSwitch,
        link=Link,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    net.addController("c0", controller=RemoteController,
                      ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    core = []
    for i in range(1, N_CORE + 1):
        core.append(net.addSwitch(f"c{i}", dpid=f"{i:016x}"))

    agg_switches  = []
    edge_switches = []
    hosts         = []

    for pod in range(N_PODS):
        pod_agg  = []
        pod_edge = []

        for a in range(N_AGG_PER_POD):
            sw_num = pod * N_AGG_PER_POD + a + 1
            sw = net.addSwitch(f"a{sw_num}", dpid=f"{0x100 + sw_num:016x}")
            pod_agg.append(sw)
        agg_switches.append(pod_agg)

        for e in range(N_EDGE_PER_POD):
            sw_num = pod * N_EDGE_PER_POD + e + 1
            sw = net.addSwitch(f"e{sw_num}", dpid=f"{0x200 + sw_num:016x}")
            pod_edge.append(sw)

            for h in range(N_HOSTS_PER_EDGE):
                host_num = (pod * N_EDGE_PER_POD * N_HOSTS_PER_EDGE
                            + e * N_HOSTS_PER_EDGE + h + 1)
                ip  = f"10.{pod}.{e}.{h + 1}"
                mac = f"00:00:00:{pod:02x}:{e:02x}:{h + 1:02x}"
                host = net.addHost(f"h{host_num}", ip=f"{ip}/24", mac=mac)
                hosts.append(host)
                net.addLink(host, sw)

        edge_switches.append(pod_edge)

    for core_idx in range(N_CORE):
        for pod in range(N_PODS):
            agg_idx = core_idx // (K // 2)
            net.addLink(core[core_idx], agg_switches[pod][agg_idx])

    for pod in range(N_PODS):
        for a in range(N_AGG_PER_POD):
            for e in range(N_EDGE_PER_POD):
                net.addLink(agg_switches[pod][a], edge_switches[pod][e])

    return net, hosts


def configure_routes(hosts: list) -> None:
    info("*** Configuring host routes\n")
    for host in hosts:
        pod = int(host.IP().split(".")[1])
        gw = f"10.{pod}.0.1"
        for other_pod in range(N_PODS):
            if other_pod != pod:
                host.cmd(f"ip route add 10.{other_pod}.0.0/16 via {gw} 2>/dev/null || true")
        host.cmd(f"ip route add 10.{pod}.0.0/24 dev {host.name}-eth0 2>/dev/null || true")


def start_baseline_traffic(hosts: list) -> None:
    """Legit-only baseline traffic. Attacker hosts stay silent.

    Phase 1 — burst: ping -c 150 -i BASELINE_BURST_INTERVAL (2 pps, ~75s)
      Ensures OVS flow table has >100 packets so the ryu_controller
      pkt_count >= 50 guard is satisfied for normal-mode submissions.

    Phase 2 — slow continuous: ping -i BASELINE_CONT_INTERVAL (0.33 pps)
      Keeps the flow alive. Well below every ML gate.
    """
    attacker_nums = {1, 5, 9, 13}
    legit = [h for h in hosts if int(h.name[1:]) not in attacker_nums]
    info(f"*** Starting baseline traffic on {len(legit)} legitimate hosts\n")
    info(f"    → burst: ping -c 150 -i {BASELINE_BURST_INTERVAL} (2 pps, ~75s)\n")
    info(f"    → then:  ping -i {BASELINE_CONT_INTERVAL} (0.33 pps, continuous)\n")
    all_ips = [h.IP() for h in legit]

    for host in legit:
        others = [ip for ip in all_ips if ip != host.IP()]
        if not others:
            continue
        target = random.choice(others)
        host.cmd(
            f"ping -c 150 -i {BASELINE_BURST_INTERVAL} {target} > /dev/null 2>&1 &"
        )
        host.cmd(
            f"ping -i {BASELINE_CONT_INTERVAL} {target} > /dev/null 2>&1 &"
        )


# ==================================================================
# SINGLE ATTACKS
# ==================================================================

def launch_syn_flood(net, attacker_name="h1", victim_name="h2", duration=60):
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** SYN Flood ({ATTACK_PKT_COUNT:,} pkts): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    attacker.cmd(
        f"hping3 -S -p 80 --flood -c {ATTACK_PKT_COUNT} --rand-source {victim.IP()} "
        f"> /dev/null 2>&1 &"
    )


def launch_icmp_flood(net, attacker_name="h5", victim_name="h6", duration=60):
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** ICMP Flood ({ATTACK_PKT_COUNT:,} pkts): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    attacker.cmd(
        f"hping3 --icmp --flood -c {ATTACK_PKT_COUNT} --rand-source {victim.IP()} "
        f"> /dev/null 2>&1 &"
    )


def launch_udp_flood(net, attacker_name="h9", victim_name="h10", duration=60):
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** UDP Flood ({ATTACK_PKT_COUNT:,} pkts): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    attacker.cmd(
        f"hping3 --udp -p 53 --flood -c {ATTACK_PKT_COUNT} --rand-source {victim.IP()} "
        f"> /dev/null 2>&1 &"
    )


# ==================================================================
# CAMPAIGNS
# ==================================================================

def start_syn_flood_campaign(net):
    info("*** [CAMPAIGN] SYN Flood — 4 attackers, unlimited, random sources\n")
    for att, vic in _CAMPAIGNS:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) → {vic}({victim.IP()})  [SYN --flood]\n")
        attacker.cmd(
            f"hping3 -S -p 80 --flood --rand-source {victim.IP()} > /dev/null 2>&1 &"
        )
    info("    → Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_icmp_flood_campaign(net):
    info("*** [CAMPAIGN] ICMP Flood — 4 attackers, unlimited, random sources\n")
    for att, vic in _CAMPAIGNS:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) → {vic}({victim.IP()})  [ICMP --flood]\n")
        attacker.cmd(
            f"hping3 --icmp --flood --rand-source {victim.IP()} > /dev/null 2>&1 &"
        )
    info("    → Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_udp_flood_campaign(net):
    info("*** [CAMPAIGN] UDP Flood — 4 attackers, unlimited, random sources\n")
    for att, vic in _CAMPAIGNS:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) → {vic}({victim.IP()})  [UDP --flood]\n")
        attacker.cmd(
            f"hping3 --udp -p 53 --flood --rand-source {victim.IP()} > /dev/null 2>&1 &"
        )
    info("    → Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_mixed_campaign(net):
    info("*** [CAMPAIGN] Mixed DDoS — SYN + ICMP + UDP simultaneously\n")
    campaigns = [
        ("h1",  "h2",  "hping3 -S -p 80 --flood --rand-source",   "SYN Flood"),
        ("h5",  "h6",  "hping3 --icmp --flood --rand-source",      "ICMP Flood"),
        ("h9",  "h10", "hping3 --udp -p 53 --flood --rand-source", "UDP Flood"),
        ("h13", "h14", "hping3 -S -p 443 --flood --rand-source",   "SYN Flood (p443)"),
    ]
    for att, vic, cmd_prefix, label in campaigns:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) → {vic}({victim.IP()})  [{label}]\n")
        attacker.cmd(f"{cmd_prefix} {victim.IP()} > /dev/null 2>&1 &")
    info("    → Running. Use  py stop_all_attacks(net)  to stop.\n")


# ==================================================================
# STOP
# ==================================================================

def stop_all_attacks(net):
    info("*** Stopping all attacks...\n")
    for att, _ in _CAMPAIGNS:
        try:
            net.get(att).cmd("pkill -f hping3 2>/dev/null; true")
            info(f"    {att}: stopped\n")
        except Exception:
            pass

    info("*** Flushing OVS block/quarantine rules...\n")
    import subprocess
    for sw in net.switches:
        for pri in [100, 90, 80]:
            subprocess.run(
                f"ovs-ofctl del-flows {sw.name} priority={pri}",
                shell=True, capture_output=True
            )
    info("    Done — forwarding restored.\n")


def stop_baseline(net):
    info("*** Stopping baseline traffic...\n")
    attacker_nums = {1, 5, 9, 13}
    for h in net.hosts:
        if int(h.name[1:]) not in attacker_nums:
            h.cmd("pkill -f ping 2>/dev/null; true")
    info("    Done.\n")


# ==================================================================
# TRAFFIC HEALTH CHECK
# ==================================================================

def check_traffic(net) -> None:
    attacker_nums = {1, 5, 9, 13}
    info("\n" + "=" * 70 + "\n")
    info("  TRAFFIC HEALTH CHECK\n")
    info("=" * 70 + "\n")
    info(f"  {'HOST':<6} {'IP':<16} {'ROLE':<12} {'PING→GW':<10} STATUS\n")
    info("  " + "-" * 65 + "\n")

    all_ok   = True
    problems = []

    for h in net.hosts:
        is_attacker = int(h.name[1:]) in attacker_nums
        role = "ATTACKER" if is_attacker else "legit"
        ip   = h.IP()
        pod  = int(ip.split(".")[1])
        gw   = f"10.{pod}.0.1" if not ip.endswith(".1") else f"10.{pod}.0.2"

        ret     = h.cmd(f"ping -c1 -W1 {gw} > /dev/null 2>&1; echo $?").strip()
        ping_ok = (ret == "0")

        if is_attacker:
            ping_str = "✓ ok" if ping_ok else "✗ FAIL"
            status   = "ready to attack"
            info(f"  {h.name:<6} {ip:<16} {role:<12} {ping_str:<10} {status}\n")
        else:
            ps_out  = h.cmd("ps aux | grep 'ping -i' | grep -v grep").strip()
            running = bool(ps_out)

            ping_str = "✓ ok" if ping_ok else "✗ FAIL"
            if not ping_ok:
                all_ok = False
                problems.append(f"{h.name} ({ip}): gateway unreachable")

            status = "✓ baseline running" if running else "⚠ baseline NOT running"
            if not running:
                all_ok = False
                problems.append(f"{h.name} ({ip}): baseline ping stopped")

            info(f"  {h.name:<6} {ip:<16} {role:<12} {ping_str:<10} {status}\n")

    info("=" * 70 + "\n")
    if all_ok:
        info("  ✓ All hosts healthy — normal traffic confirmed.\n")
    else:
        info("  ⚠ Issues detected:\n")
        for p in problems:
            info(f"    • {p}\n")
        info("  → Run  py start_baseline_traffic(hosts)  to restart baseline.\n")
    info("=" * 70 + "\n\n")


def _print_traffic_health(hosts: list) -> None:
    attacker_nums = {1, 5, 9, 13}
    info("\n" + "=" * 70 + "\n")
    info("  HOST TRAFFIC STATUS (post-warmup)\n")
    info("=" * 70 + "\n")
    info(f"  {'HOST':<6} {'IP':<16} {'ROLE':<12} BASELINE\n")
    info("  " + "-" * 55 + "\n")
    for h in hosts:
        is_attacker = int(h.name[1:]) in attacker_nums
        role = "★ ATTACKER" if is_attacker else "  legit"
        if is_attacker:
            info(f"  {h.name:<6} {h.IP():<16} {role:<12} — (attack host)\n")
        else:
            ps = h.cmd("ps aux | grep 'ping -i' | grep -v grep").strip()
            status = "✓ ping running" if ps else "⚠ NOT running"
            info(f"  {h.name:<6} {h.IP():<16} {role:<12} {status}\n")
    info("=" * 70 + "\n")
    info("  → CLI ready. Use  py check_traffic(net)  to re-check anytime.\n")
    info("=" * 70 + "\n\n")


def _warmup_macs(net, hosts, max_rounds: int = 2) -> None:
    subnet_groups: dict = {}
    for h in hosts:
        subnet = ".".join(h.IP().split(".")[:3])
        subnet_groups.setdefault(subnet, []).append(h)

    total = sum(len(g) * (len(g) - 1) for g in subnet_groups.values())
    info(f"*** MAC warmup — pinging {total} local pairs (low-overhead mode)...\n")

    for rnd in range(1, max_rounds + 1):
        info(f"    Round {rnd}/{max_rounds} ...\n")
        procs = []
        for group in subnet_groups.values():
            for src in group:
                for dst in group:
                    if src is dst:
                        continue
                    p = src.popen(
                        f"ping -c1 -W1 {dst.IP()} > /dev/null 2>&1", shell=True)
                    procs.append(p)
        for p in procs:
            p.wait()

    info("*** Warmup done — edge MACs populated.\n")
    _print_traffic_health(hosts)


def _print_banner(hosts: list) -> None:
    info("\n" + "=" * 70 + "\n")
    info("  Fat-Tree k=4  |  20 switches  |  16 hosts\n")
    info("=" * 70 + "\n")
    info(f"  {'HOST':<6} {'IP':<16} {'MAC':<20} ROLE\n")
    info("  " + "-" * 65 + "\n")
    for h in hosts:
        role = "★ ATTACKER" if int(h.name[1:]) in {1, 5, 9, 13} else "  legit"
        info(f"  {h.name:<6} {h.IP():<16} {h.MAC():<20} {role}\n")
    info("=" * 70 + "\n\n")
    # M10 fix: banner now shows accurate rates derived from the constants
    info(f"  BASELINE:\n")
    info(f"    burst:  ping -c 150 -i {BASELINE_BURST_INTERVAL} (2 pps, ~75s)\n")
    info(f"    then:   ping -i {BASELINE_CONT_INTERVAL} (0.33 pps, continuous)\n\n")

    info("  ── SINGLE ATTACK ─────────────────────────────────────────────────\n\n")
    info(f"    py launch_syn_flood(net, 'h1', 'h2')     # {ATTACK_PKT_COUNT:,} SYN pkts\n")
    info(f"    py launch_icmp_flood(net, 'h5', 'h6')    # {ATTACK_PKT_COUNT:,} ICMP pkts\n")
    info(f"    py launch_udp_flood(net, 'h9', 'h10')    # {ATTACK_PKT_COUNT:,} UDP pkts\n\n")

    info("  ── CAMPAIGN (4 attackers, UNLIMITED) ─────────────────────────────\n\n")
    info("    py start_syn_flood_campaign(net)   # → RF: SYN Flood\n")
    info("    py start_icmp_flood_campaign(net)  # → RF: ICMP Flood\n")
    info("    py start_udp_flood_campaign(net)   # → RF: UDP Flood\n")
    info("    py start_mixed_campaign(net)       # → RF: all 3 types\n\n")

    info("  ── STOP ──────────────────────────────────────────────────────────\n\n")
    info("    py stop_all_attacks(net)   # kill hping3 + flush OVS rules\n")
    info("    py stop_baseline(net)      # kill all ping\n\n")

    info("  ── OTHER ─────────────────────────────────────────────────────────\n\n")
    info("    py check_traffic(net)  # live host health table\n")
    info("    pingall\n")
    info("    h1 ping -c3 10.0.0.2\n")
    info("    dump / net / exit\n")
    info("=" * 70 + "\n\n")


# ==================================================================
# Feature 2: Auto-restoration of baseline traffic after manual unquarantine
# ==================================================================

import threading
import urllib.request
import json as _json
import logging as _logging

BACKEND_API    = "http://127.0.0.1:5000"
RESTORE_POLL_S = 5.0
_restore_log   = _logging.getLogger("restore_poller")


def restore_baseline_for_ip(hosts: list, src_ip: str) -> bool:
    """Restart baseline ping for the host with the given IP.

    Called when the backend signals a manually-released host needs
    its traffic restarted.
    """
    for host in hosts:
        if host.IP() == src_ip:
            host.cmd("pkill -f 'ping -i' 2>/dev/null; true")
            attacker_nums = {1, 5, 9, 13}
            others = [
                h.IP() for h in hosts
                if h.IP() != src_ip and int(h.name[1:]) not in attacker_nums
            ]
            if not others:
                _restore_log.warning(
                    "No valid target for %s baseline restore", src_ip
                )
                return False
            target = random.choice(others)
            host.cmd(
                f"ping -i {BASELINE_CONT_INTERVAL} {target} > /dev/null 2>&1 &"
            )
            _restore_log.info(
                "Restored baseline for %s → %s (ping -i %s)",
                src_ip, target, BASELINE_CONT_INTERVAL
            )
            return True
    _restore_log.warning("Host %s not found — skipping restore", src_ip)
    return False


def _restore_poller_loop(hosts: list) -> None:
    while True:
        time.sleep(RESTORE_POLL_S)
        try:
            url = f"{BACKEND_API}/api/pending_restores"
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = _json.loads(resp.read())
            for ip in data.get("ips", []):
                restore_baseline_for_ip(hosts, ip)
        except Exception as exc:
            _restore_log.debug("Restore poller error: %s", exc)


def _start_restore_poller(hosts: list) -> None:
    """Start the auto-restoration poller. Call once just before TopologyCLI(net)."""
    t = threading.Thread(
        target=_restore_poller_loop,
        args=(hosts,),
        name="restore-poller",
        daemon=True,
    )
    t.start()
    info(f"*** Auto-restore poller started (polling {BACKEND_API} every "
         f"{RESTORE_POLL_S:.0f}s)\n")


# ==================================================================
# Entry point
# ==================================================================

if __name__ == "__main__":
    setLogLevel("info")

    global net
    net, hosts = build_fat_tree()
    net.start()

    info("*** Waiting for switches to connect to Ryu...\n")
    time.sleep(3)

    _print_banner(hosts)

    info("*** Starting baseline normal traffic...\n")
    start_baseline_traffic(hosts)
    time.sleep(1)

    _warmup_macs(net, hosts)

    info("*** Restarting baseline post-warmup...\n")
    start_baseline_traffic(hosts)

    # Feature 2: start restore poller before handing off to CLI
    _start_restore_poller(hosts)

    info("*** Network ready — starting CLI.\n\n")

    _g = globals().copy()
    _g.update({"net": net, "hosts": hosts})

    class TopologyCLI(CLI):
        def do_py(self, line):
            try:
                result = eval(line, _g)
                if result is not None:
                    print(result)
            except SyntaxError:
                try:
                    exec(line, _g)
                except Exception as e:
                    print(f"Error: {e}")
            except Exception as e:
                print(f"Error: {e}")

    TopologyCLI(net)
    net.stop()