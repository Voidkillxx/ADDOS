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
# BASELINE_BURST_INTERVAL: initial burst phase — 20 pps for ~5s
# Quickly fills OVS flow table and makes traffic visible on dashboard immediately.
BASELINE_BURST_INTERVAL = "0.05"  # ping -i 0.05 → 20 pps

# BASELINE_CONT_INTERVAL: continuous traffic after burst — ~10 pps per stream
# 3 streams x 10 pps = ~30 pps/host total -> clearly visible on dashboard.
# Each stream targets a different IP so no single switch sees all 30 pps from one IP.
# Still safely classified as Normal by Isolation Forest (spread across 3 targets).
BASELINE_CONT_INTERVAL  = "0.1"   # ping -i 0.1 -> 10 pps per stream

# Attack volume for single (finite) attacks.
ATTACK_PKT_COUNT = 5000   # 5k pkts at --flood takes ~2-3s in Mininet VM

# 8/8 split: 8 attackers, 8 legit hosts
# Attackers: h1,h3,h5,h7,h9,h11,h13,h15 (odd hosts)
# Legit:     h2,h4,h6,h8,h10,h12,h14,h16 (even hosts)
_ATTACKER_NUMS = {1, 3, 5, 7, 9, 11, 13, 15}

_CAMPAIGNS = [
    ("h1",  "h2"),    # SYN
    ("h13", "h14"),   # SYN
    ("h5",  "h6"),    # ICMP
    ("h3",  "h4"),    # ICMP
    ("h9",  "h10"),   # UDP
    ("h7",  "h8"),    # UDP
    ("h11", "h12"),   # SYN extra
    ("h15", "h16"),   # UDP extra
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


def _get_baseline_target(host, hosts: list) -> str:
    """Pick the best ping target for a host's baseline traffic.

    Priority:
      1. Legit host on SAME POD, different edge (3 hops — reliable after warmup).
      2. Any legit host cross-pod (5 hops — populated by warmup Phase 2).
    """
    my_ip  = host.IP()
    parts  = my_ip.split(".")
    my_pod = parts[1]
    my_sub = ".".join(parts[:3])

    # Pass 1: legit host, same pod, different edge switch
    for other in hosts:
        if other is host:
            continue
        if int(other.name[1:]) in _ATTACKER_NUMS:
            continue
        op = other.IP().split(".")
        if op[1] == my_pod and ".".join(op[:3]) != my_sub:
            return other.IP()

    # Pass 2: any legit host cross-pod
    for other in hosts:
        if other is host:
            continue
        if int(other.name[1:]) not in _ATTACKER_NUMS:
            return other.IP()

    return host.IP()  # should never happen


def start_baseline_traffic(hosts: list) -> None:
    """Legit-only baseline traffic. Attacker hosts stay silent.

    Phase 1 — burst: ping -c 100 -i BASELINE_BURST_INTERVAL (10 pps, ~10s)
      Quickly fills OVS flow table and makes traffic immediately visible.

    Phase 2 — continuous: 3 parallel ping streams at ~5 pps each (~15 pps/host)
      Clearly visible in Live Traffic Monitor. Each stream targets a different IP
      so no single switch sees all 15 pps from one src — stays Normal to ML model.

    BUG FIX: ping -c 300 (no sleep) so continuous ping has no gaps between batches.
    """
    attacker_nums = _ATTACKER_NUMS
    legit = [h for h in hosts if int(h.name[1:]) not in attacker_nums]
    info(f"*** Starting baseline traffic on {len(legit)} legitimate hosts\n")
    info(f"    → burst:  ping -c 100 -i {BASELINE_BURST_INTERVAL} (10 pps, ~10s)\n")
    info(f"    → then:   3x ping -i {BASELINE_CONT_INTERVAL} (~5 pps each → ~15 pps/host)\n")

    for host in legit:
        target = _get_baseline_target(host, hosts)
        # Kill any stale ping processes before starting fresh
        host.cmd("pkill -f 'ping -c 50' 2>/dev/null; pkill -f 'ping -c 300' 2>/dev/null; pkill -f 'baseline-ping' 2>/dev/null; true")

        # Burst phase — 50 pkts at 20 pps = ~2.5s, fills flow table fast
        host.cmd(
            f"ping -c 50 -i {BASELINE_BURST_INTERVAL} {target} > /dev/null 2>&1 &"
        )

        # Stream 1: infinite ping at 5 pps — no -c so it never races against flow idle_timeout
        host.cmd(
            f"ping -i {BASELINE_CONT_INTERVAL} {target} > /dev/null 2>&1 &"
        )

        # Stream 2: second legit target for more visible baseline traffic
        other_hosts = [h for h in hosts if h is not host and h.IP() != target
                       and int(h.name[1:]) not in _ATTACKER_NUMS]
        if other_hosts:
            target2 = other_hosts[0].IP()
            host.cmd(
                f"ping -i {BASELINE_CONT_INTERVAL} {target2} > /dev/null 2>&1 &"
            )

        # Stream 3: third legit target — spreads traffic across subnets
        if len(other_hosts) > 1:
            target3 = other_hosts[1].IP()
            host.cmd(
                f"ping -i {BASELINE_CONT_INTERVAL} {target3} > /dev/null 2>&1 &"
            )


# ==================================================================
# SINGLE ATTACKS
# ==================================================================

def launch_syn_flood(net, attacker_name="h1", victim_name="h2", duration=60):
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** SYN Flood ({ATTACK_PKT_COUNT:,} pkts, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    attacker.cmd(
        f"hping3 -S -p 80 --flood -c {ATTACK_PKT_COUNT} {victim.IP()} "
        f"> /dev/null 2>&1 &"
    )


def launch_icmp_flood(net, attacker_name="h5", victim_name="h6", duration=60):
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** ICMP Flood ({ATTACK_PKT_COUNT:,} pkts, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    attacker.cmd(
        f"hping3 --icmp --flood -c {ATTACK_PKT_COUNT} {victim.IP()} "
        f"> /dev/null 2>&1 &"
    )


def launch_udp_flood(net, attacker_name="h9", victim_name="h10", duration=60):
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** UDP Flood ({ATTACK_PKT_COUNT:,} pkts, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    attacker.cmd(
        f"hping3 --udp -p 53 --flood -c {ATTACK_PKT_COUNT} {victim.IP()} "
        f"> /dev/null 2>&1 &"
    )


def launch_syn_flood_sustained(net, attacker_name="h1", victim_name="h2"):
    """Unlimited SYN flood — runs until stop_all_attacks(). Simulates persistent DDoS."""
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** SYN Flood SUSTAINED (unlimited, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    info("    → Use  py stop_all_attacks(net)  to stop.\n")
    attacker.cmd(
        f"hping3 -S -p 80 --flood {victim.IP()} > /dev/null 2>&1 &"
    )


def launch_icmp_flood_sustained(net, attacker_name="h5", victim_name="h6"):
    """Unlimited ICMP flood — runs until stop_all_attacks(). Simulates persistent DDoS."""
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** ICMP Flood SUSTAINED (unlimited, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    info("    → Use  py stop_all_attacks(net)  to stop.\n")
    attacker.cmd(
        f"hping3 --icmp --flood {victim.IP()} > /dev/null 2>&1 &"
    )


def launch_udp_flood_sustained(net, attacker_name="h9", victim_name="h10"):
    """Unlimited UDP flood — runs until stop_all_attacks(). Simulates persistent DDoS."""
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** UDP Flood SUSTAINED (unlimited, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    info("    → Use  py stop_all_attacks(net)  to stop.\n")
    attacker.cmd(
        f"hping3 --udp -p 53 --flood {victim.IP()} > /dev/null 2>&1 &"
    )


# ==================================================================
# CAMPAIGNS
# ==================================================================

def start_syn_flood_campaign(net):
    info("*** [CAMPAIGN] SYN Flood — 3 attackers, varied params, fixed IPs\n")
    _syn = [
        ("h1",  "h2",  "hping3 -S -p 80   --flood  "),
        ("h13", "h14", "hping3 -S -p 443  --flood "),
        ("h11", "h12", "hping3 -S -p 8080 --flood  "),
    ]
    for att, vic, cmd in _syn:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) -> {vic}({victim.IP()})  [{cmd.strip()}]\n")
        attacker.cmd(cmd + victim.IP() + " > /dev/null 2>&1 &")
    info("    -> Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_icmp_flood_campaign(net):
    info("*** [CAMPAIGN] ICMP Flood — 2 attackers, varied params, fixed IPs\n")
    _icmp = [
        ("h5", "h6", "hping3 --icmp --flood          "),
        ("h3", "h4", "hping3 --icmp --flood --data 120 "),
    ]
    for att, vic, cmd in _icmp:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) -> {vic}({victim.IP()})  [{cmd.strip()}]\n")
        attacker.cmd(cmd + victim.IP() + " > /dev/null 2>&1 &")
    info("    -> Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_udp_flood_campaign(net):
    info("*** [CAMPAIGN] UDP Flood — 3 attackers, varied params, fixed IPs\n")
    _udp = [
        ("h9",  "h10", "hping3 --udp -p 53  --flood  "),
        ("h7",  "h8",  "hping3 --udp -p 80  --flood "),
        ("h15", "h16", "hping3 --udp -p 443 --flood  "),
    ]
    for att, vic, cmd in _udp:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) -> {vic}({victim.IP()})  [{cmd.strip()}]\n")
        attacker.cmd(cmd + victim.IP() + " > /dev/null 2>&1 &")
    info("    -> Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_mixed_campaign(net):
    info("*** [CAMPAIGN] Mixed DDoS — SYN + ICMP + UDP simultaneously, fixed IPs\n")
    campaigns = [
        ("h1",  "h2",  "hping3 -S -p 80   --flood",       "SYN Flood"),
        ("h13", "h14", "hping3 -S -p 443  --flood",       "SYN Flood (p443)"),
        ("h11", "h12", "hping3 -S -p 8080 --flood",        "SYN Flood (p8080)"),
        ("h5",  "h6",  "hping3 --icmp --flood",            "ICMP Flood"),
        ("h3",  "h4",  "hping3 --icmp --flood --data 120", "ICMP Flood (large)"),
        ("h9",  "h10", "hping3 --udp -p 53  --flood",      "UDP Flood"),
        ("h7",  "h8",  "hping3 --udp -p 80  --flood",      "UDP Flood (p80)"),
        ("h15", "h16", "hping3 --udp -p 443 --flood",      "UDP Flood (p443)"),
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

    # ── BUG FIX: clear banned-IP state in the Ryu controller ─────────────────
    # Previously stop_all_attacks() only flushed OVS flow rules but never told
    # the controller to clear self._banned_ips. The controller kept silently
    # dropping packets from attacker IPs via the throttled fast-path, and the
    # backend's threat state machine never saw the attack end → dashboard kept
    # showing "Active Threats: 1 — Currently being mitigated" indefinitely.
    #
    # Fix: send a ZMQ "clear" command for every attacker IP so the controller
    # removes them from _banned_ips and _blocked_prev_pkts, and the backend
    # receives a clean slate signal to close out the active threat entry.
    info("*** Clearing controller banned-IP state via ZMQ...\n")
    try:
        import zmq as _zmq
        _ctx  = _zmq.Context.instance()
        _sock = _ctx.socket(_zmq.PUSH)
        _sock.setsockopt(_zmq.LINGER, 0)
        _sock.setsockopt(_zmq.SNDTIMEO, 500)
        _sock.connect("tcp://127.0.0.1:5556")
        attacker_ips = []
        for att, _ in _CAMPAIGNS:
            try:
                attacker_ips.append(net.get(att).IP())
            except Exception:
                pass
        for ip in attacker_ips:
            _sock.send_json({"action": "clear", "src_ip": ip})
            info(f"    cleared: {ip}\n")
        _sock.close()
        info("    Controller state cleared.\n")
        # BUG FIX: wait for controller cooldown intervals to tick down before
        # baseline restarts. Without this, the first baseline pings arrive while
        # switch_delta_pps is still elevated from the attack, causing them to be
        # misclassified as flood traffic. 4s = 3 x STATS_INTERVAL(1.0s) + 1s buffer.
        info("*** Waiting 4s for controller cooldown (prevents baseline false-positive)...\n")
        time.sleep(4)
        info("    Cooldown complete — safe to restart baseline traffic.\n")
    except Exception as e:
        info(f"    Warning: could not clear controller state via ZMQ: {e}\n")
        info("    (OVS rules are flushed; backend will self-clear after TTL expiry)\n")


def stop_baseline(net):
    info("*** Stopping baseline traffic...\n")
    for h in net.hosts:
        if int(h.name[1:]) not in _ATTACKER_NUMS:
            h.cmd("pkill -f ping 2>/dev/null; true")
    info("    Done.\n")


# ==================================================================
# TRAFFIC HEALTH CHECK
# ==================================================================

def _get_ping_neighbor(h, net) -> str:
    """Return the IP of the nearest reachable neighbor for connectivity check."""
    attacker_nums = _ATTACKER_NUMS
    my_ip   = h.IP()
    parts   = my_ip.split(".")
    my_pod  = parts[1]
    my_sub  = ".".join(parts[:3])

    # Pass 1: ANY host on same /24 (same edge switch — direct L2, 1 hop).
    for other in net.hosts:
        if other is h:
            continue
        if ".".join(other.IP().split(".")[:3]) == my_sub:
            return other.IP()

    # Pass 2: legit host, same pod, different edge (agg switch path)
    for other in net.hosts:
        if other is h:
            continue
        if int(other.name[1:]) in attacker_nums:
            continue
        op = other.IP().split(".")
        if op[1] == my_pod and ".".join(op[:3]) != my_sub:
            return other.IP()

    # Pass 3: any legit host cross-pod (core switch path)
    for other in net.hosts:
        if other is h:
            continue
        if int(other.name[1:]) not in attacker_nums:
            return other.IP()

    return my_ip   # should never happen


def _fetch_quarantine() -> dict:
    """Fetch active quarantine list from backend."""
    try:
        url = f"{BACKEND_API}/api/quarantine_list"
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = _json.loads(resp.read())
        return {e["src_ip"]: e["phase"] for e in data}
    except Exception:
        return {}


def _fetch_stats() -> dict:
    """Fetch live stats from backend (active threats, malicious dropped, fp_rate)."""
    try:
        url = f"{BACKEND_API}/api/stats"
        with urllib.request.urlopen(url, timeout=2) as resp:
            return _json.loads(resp.read())
    except Exception:
        return {}


def check_traffic(net) -> None:
    """Live traffic health check with real-time mitigation status from backend."""
    attacker_nums = _ATTACKER_NUMS

    quarantine = _fetch_quarantine()
    stats      = _fetch_stats()
    backend_up = bool(stats)

    info("\n" + "=" * 75 + "\n")
    info("  TRAFFIC HEALTH CHECK\n")
    info("=" * 75 + "\n")

    if backend_up:
        threats  = stats.get("active_threats", 0)
        dropped  = stats.get("malicious_dropped", 0)
        fp_rate  = stats.get("fp_rate", 0.0)
        info(f"  Backend: ONLINE  |  Active threats: {threats}"
             f"  |  Malicious dropped: {dropped}"
             f"  |  FP rate: {fp_rate:.1f}%\n")
    else:
        info("  Backend: OFFLINE (mitigation status unavailable)\n")

    info("=" * 75 + "\n")
    info(f"  {'HOST':<6} {'IP':<16} {'ROLE':<12} {'PING':<8} MITIGATION / STATUS\n")
    info("  " + "-" * 70 + "\n")

    all_ok   = True
    problems = []

    for h in net.hosts:
        is_attacker = int(h.name[1:]) in attacker_nums
        role        = "ATTACKER" if is_attacker else "legit"
        ip          = h.IP()

        if is_attacker:
            ping_str = "—"
            ping_ok  = True
        else:
            neighbor = _get_ping_neighbor(h, net)
            ret      = h.cmd(f"ping -c1 -W2 {neighbor} > /dev/null 2>&1; echo $?").strip()
            ping_ok  = (ret == "0")
            ping_str = "✓ ok" if ping_ok else "✗ FAIL"

        if ip in quarantine:
            phase       = quarantine[ip]
            mit_status  = f"⚡ MITIGATED — {phase}"
        else:
            mit_status  = None

        if is_attacker:
            hping_out    = h.cmd("pgrep -x hping3 2>/dev/null").strip()
            is_attacking = bool(hping_out)

            if is_attacking:
                if mit_status:
                    status_str = f"★ ATTACKING  [{mit_status}]"
                else:
                    status_str = "★ ATTACKING"
            else:
                status_str = "— standby (no attack running)"
            info(f"  {h.name:<6} {ip:<16} {role:<12} {ping_str:<8} {status_str}\n")

        else:
            ps_out  = h.cmd("ps aux | grep 'ping -i' | grep -v grep").strip()
            running = bool(ps_out)

            if not ping_ok:
                all_ok = False
                problems.append(f"{h.name} ({ip}): unreachable")

            if mit_status:
                status_str = f"⚠ FP? {mit_status}"
                all_ok = False
                problems.append(f"{h.name} ({ip}): legit host under mitigation — possible false positive")
            elif running:
                status_str = "✓ baseline running"
            else:
                status_str = "⚠ baseline NOT running"
                all_ok = False
                problems.append(f"{h.name} ({ip}): baseline ping stopped")

            info(f"  {h.name:<6} {ip:<16} {role:<12} {ping_str:<8} {status_str}\n")

    info("=" * 75 + "\n")
    if all_ok:
        info("  ✓ All hosts healthy — normal traffic confirmed.\n")
    else:
        info("  ⚠ Issues detected:\n")
        for p in problems:
            info(f"    • {p}\n")
        info("\n  Notes:\n")
        info("    • ⚡ MITIGATED during attack = system working correctly.\n")
        info("    • ⚠ FP? = legit host mitigated — press Release in dashboard.\n")
        info("    • ✗ FAIL ping during flood = expected (network congestion).\n")
        info("    • 'baseline NOT running' after attack: run\n")
        info("        py stop_all_attacks(net)\n")
        info("        py start_baseline_traffic(hosts)\n")
    info("=" * 75 + "\n\n")


def _print_traffic_health(hosts: list) -> None:
    attacker_nums = _ATTACKER_NUMS
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
    """Populate OVS MAC/forwarding tables across ALL switches before CLI starts."""
    attacker_nums = _ATTACKER_NUMS
    legit_hosts   = [h for h in hosts if int(h.name[1:]) not in attacker_nums]

    subnet_groups: dict = {}
    for h in hosts:
        subnet = ".".join(h.IP().split(".")[:3])
        subnet_groups.setdefault(subnet, []).append(h)

    local_total = sum(len(g) * (len(g) - 1) for g in subnet_groups.values())
    info(f"*** Phase 1 warmup — {local_total} local pairs (edge switches)...\n")

    # Launch ALL pings simultaneously — don't wait between them
    procs = []
    for group in subnet_groups.values():
        for src in group:
            for dst in group:
                if src is dst:
                    continue
                p = src.popen(
                    f"ping -c1 -W1 {dst.IP()} > /dev/null 2>&1", shell=True)
                procs.append(p)
    # Wait with a hard cap — never block more than 4s total for Phase 1
    _deadline = time.time() + 4.0
    for p in procs:
        _left = max(0.1, _deadline - time.time())
        try:
            p.wait(timeout=_left)
        except Exception:
            p.kill()

    info("*** Phase 1 done — edge switch tables populated.\n")

    # Phase 2: cross-subnet — only use a SAMPLE of pairs (not all 56+)
    # Full cross-product causes 1-2min delay. A sample of 16 pairs is enough
    # to populate agg/core switch MAC tables without blocking the CLI.
    cross_all = [
        (src, dst)
        for src in legit_hosts
        for dst in legit_hosts
        if src is not dst
        and ".".join(src.IP().split(".")[:3]) != ".".join(dst.IP().split(".")[:3])
    ]
    # Pick one cross-subnet pair per legit host (covers all pods with minimal pings)
    seen_srcs = set()
    cross_sample = []
    for src, dst in cross_all:
        if src.name not in seen_srcs:
            cross_sample.append((src, dst))
            seen_srcs.add(src.name)

    info(f"*** Phase 2 warmup — {len(cross_sample)} cross-subnet pairs (agg + core switches)...\n")
    info("    (sampled, ping -c1 -W1, max 4s)\n")

    procs = []
    for src, dst in cross_sample:
        p = src.popen(
            f"ping -c1 -W1 {dst.IP()} > /dev/null 2>&1", shell=True)
        procs.append(p)
    # Hard cap of 4s for Phase 2 too
    _deadline = time.time() + 4.0
    for p in procs:
        _left = max(0.1, _deadline - time.time())
        try:
            p.wait(timeout=_left)
        except Exception:
            p.kill()

    info("*** Phase 2 done — agg/core switch tables populated.\n")
    info("*** All paths learned — hosts should be fully reachable.\n")
    _print_traffic_health(hosts)


def _print_banner(hosts: list) -> None:
    info("\n" + "=" * 70 + "\n")
    info("  Fat-Tree k=4  |  20 switches  |  16 hosts\n")
    info("=" * 70 + "\n")
    info(f"  {'HOST':<6} {'IP':<16} {'MAC':<20} ROLE\n")
    info("  " + "-" * 65 + "\n")
    for h in hosts:
        role = "★ ATTACKER" if int(h.name[1:]) in _ATTACKER_NUMS else "  legit"
        info(f"  {h.name:<6} {h.IP():<16} {h.MAC():<20} {role}\n")
    info("=" * 70 + "\n\n")
    info(f"  BASELINE:\n")
    info(f"    burst:  ping -c 150 -i {BASELINE_BURST_INTERVAL} (5 pps, ~30s)\n")
    info(f"    then:   3x ping -i {BASELINE_CONT_INTERVAL} (~3 pps each → ~9 pps/host, continuous)\n\n")

    info("  ── SINGLE BURST (finite — shows full Phase 1→2→3 pipeline) ──────\n\n")
    info(f"    py launch_syn_flood(net)             # {ATTACK_PKT_COUNT:,} SYN pkts, h1→h2\n")
    info(f"    py launch_icmp_flood(net)            # {ATTACK_PKT_COUNT:,} ICMP pkts, h5→h6\n")
    info(f"    py launch_udp_flood(net)             # {ATTACK_PKT_COUNT:,} UDP pkts, h9→h10\n\n")

    info("  ── SINGLE SUSTAINED (unlimited — real-world persistent DDoS) ────\n\n")
    info("    py launch_syn_flood_sustained(net)   # SYN, unlimited, h1→h2\n")
    info("    py launch_icmp_flood_sustained(net)  # ICMP, unlimited, h5→h6\n")
    info("    py launch_udp_flood_sustained(net)   # UDP, unlimited, h9→h10\n\n")

    info("  ── CAMPAIGN (multiple attackers simultaneously, UNLIMITED) ───────\n\n")
    info("    py start_syn_flood_campaign(net)     # → RF: SYN Flood\n")
    info("    py start_icmp_flood_campaign(net)    # → RF: ICMP Flood\n")
    info("    py start_udp_flood_campaign(net)     # → RF: UDP Flood\n")
    info("    py start_mixed_campaign(net)         # → RF: all 3 types\n\n")

    info("  ── STOP ──────────────────────────────────────────────────────────\n\n")
    info("    py stop_all_attacks(net)             # kill hping3 + flush OVS + clear controller\n")
    info("    py stop_baseline(net)                # kill all ping\n\n")

    info("  ── OTHER ─────────────────────────────────────────────────────────\n\n")
    info("    py check_traffic(net)             # live host health + mitigation status\n")
    info("    py watch_pipeline(net)            # live IF/RF scores per IP (debug)\n")
    info("    py watch_pipeline(net, anomaly_only=True)  # anomalies only\n")
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
    """Restart baseline ping for the host with the given IP."""
    for host in hosts:
        if host.IP() == src_ip:
            # Kill any leftover finite-count or infinite pings for this host
            host.cmd("pkill -f 'ping -c 50' 2>/dev/null; pkill -f 'ping -c 300' 2>/dev/null; pkill -f 'ping -i' 2>/dev/null; true")
            others = [
                h for h in hosts
                if h.IP() != src_ip and int(h.name[1:]) not in _ATTACKER_NUMS
            ]
            if not others:
                _restore_log.warning("No valid target for %s baseline restore", src_ip)
                return False

            # Restart as infinite pings — no -c so flow idle_timeout never kills a batch
            target = others[0].IP()
            host.cmd(
                f"ping -i {BASELINE_CONT_INTERVAL} {target} > /dev/null 2>&1 &"
            )
            if len(others) > 1:
                target2 = others[1].IP()
                host.cmd(
                    f"ping -i {BASELINE_CONT_INTERVAL} {target2} > /dev/null 2>&1 &"
                )
            if len(others) > 2:
                target3 = others[2].IP()
                host.cmd(
                    f"ping -i {BASELINE_CONT_INTERVAL} {target3} > /dev/null 2>&1 &"
                )
            _restore_log.info("Restored baseline for %s (3x infinite ping -i %s)", src_ip, BASELINE_CONT_INTERVAL)
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


def _baseline_watchdog_loop(hosts: list) -> None:
    """Safety net: every 30s verify each legit host has an infinite ping running.
    Restarts it if dead (e.g. killed by quarantine, OOM, or accidental pkill)."""
    import time as _wt
    _wlog = _logging.getLogger("baseline-watchdog")
    while True:
        _wt.sleep(30)
        for host in hosts:
            try:
                if int(host.name[1:]) in _ATTACKER_NUMS:
                    continue
                ps = host.cmd("pgrep -af 'ping -i' 2>/dev/null").strip()
                if not ps:
                    #_wlog.warning("Baseline dead on %s (%s) — restarting", host.name, host.IP())
                    restore_baseline_for_ip(hosts, host.IP())
            except Exception as exc:
                _wlog.debug("Watchdog check error %s: %s", host.name, exc)


def _start_restore_poller(hosts: list) -> None:
    """Start the auto-restoration poller + baseline watchdog. Call once before TopologyCLI."""
    t = threading.Thread(target=_restore_poller_loop, args=(hosts,),
                         name="restore-poller", daemon=True)
    t.start()
    info(f"*** Auto-restore poller started (polling {BACKEND_API} every {RESTORE_POLL_S:.0f}s)\n")

    w = threading.Thread(target=_baseline_watchdog_loop, args=(hosts,),
                         name="baseline-watchdog", daemon=True)
    w.start()
    info("*** Baseline watchdog started (checks every 30s)\n")


# ==================================================================
# Live pipeline debug viewer
# ==================================================================

def watch_pipeline(interval: float = 2.0, anomaly_only: bool = False,
                   n: int = 20) -> None:
    """Print live ML pipeline scores to the Mininet terminal.

    Usage (in mininet CLI):
      py watch_pipeline(net)                # all flows, refresh every 2s
      py watch_pipeline(net, anomaly_only=True)  # only anomalies
      py watch_pipeline(net, interval=1.0)  # refresh every 1s

    Press Ctrl+C to stop.
    """
    import sys
    param = "anomaly_only=1&" if anomaly_only else ""
    url   = f"{BACKEND_API}/api/debug?{param}n={n}"

    info("*** Pipeline debug viewer — press Ctrl+C to stop\n")
    info(f"    URL: {url}\n")
    info(f"    Showing: {'anomalies only' if anomaly_only else 'all flows'}"
         f"  |  refresh: {interval}s\n\n")

    try:
        while True:
            try:
                with urllib.request.urlopen(url, timeout=2) as resp:
                    data = _json.loads(resp.read())
                entries = data.get("entries", [])

                lines  = [""]
                lines.append("  " + "=" * 90)
                lines.append(f"  LIVE ML PIPELINE  —  {len(entries)} entries"
                             f"  ({'anomalies only' if anomaly_only else 'all flows'})")
                lines.append("  " + "=" * 90)
                lines.append(
                    f"  {'TIME':<9} {'SRC_IP':<16} {'PPS':>8} {'IF_SCORE':>9}"
                    f" {'THR':>7} {'ANOMALY':>8} {'CLASS':<12} {'CONF%':>6} ACTION"
                )
                lines.append("  " + "-" * 90)

                if not entries:
                    lines.append("  (no flows scanned yet — waiting for traffic above threshold)")
                else:
                    for e in entries:
                        anom    = "⚡ YES" if e.get("is_anomaly") else "  no"
                        conf    = f"{e.get('confidence', 0):.1f}%" if e.get("is_anomaly") else "—"
                        cls     = e.get("attack_class", "Normal") if e.get("is_anomaly") else "Normal"
                        action  = e.get("action", "—") or "—"
                        score   = e.get("if_score", 0)
                        thr     = e.get("threshold", 0)
                        lines.append(
                            f"  {e.get('ts','—'):<9} {e.get('src_ip','—'):<16}"
                            f" {e.get('pps', 0):>8.1f} {score:>9.4f}"
                            f" {thr:>7.4f} {anom:>8} {cls:<12} {conf:>6} {action}"
                        )

                lines.append("  " + "=" * 90)
                info("\r" + "\n".join(lines) + "\n")

            except Exception as exc:
                info(f"  [backend offline: {exc}]\n")

            time.sleep(interval)

    except KeyboardInterrupt:
        info("\n*** Pipeline viewer stopped.\n")


# ==================================================================
# Entry point
# ==================================================================

if __name__ == "__main__":
    setLogLevel("info")

    global net
    net, hosts = build_fat_tree()
    net.start()

    info("*** Waiting for switches to connect to Ryu...\n")
    _ryu_ready = False
    for _wait_i in range(20):  # 20 × 0.3s = 6s max
        time.sleep(0.3)
        try:
            import urllib.request as _ur
            with _ur.urlopen("http://127.0.0.1:8080/v1.0/topology/switches", timeout=1) as _r:
                _switches = __import__("json").loads(_r.read())
            if len(_switches) >= 20:
                info(f"*** All {len(_switches)} switches connected ({(_wait_i+1)*0.3:.1f}s)\n")
                _ryu_ready = True
                break
            else:
                info(f"    {len(_switches)}/20 switches connected...\n")
        except Exception:
            info(f"    Waiting for Ryu... ({(_wait_i+1)*0.3:.1f}s)\n")
    if not _ryu_ready:
        info("*** Timeout waiting for all switches — proceeding anyway.\n")

    _print_banner(hosts)

    info("*** Starting baseline normal traffic...\n")
    start_baseline_traffic(hosts)
    time.sleep(0.5)

    _warmup_macs(net, hosts)

    info("*** Restarting baseline post-warmup...\n")
    start_baseline_traffic(hosts)

    info("*** Waiting for baseline pings to register...\n")
    time.sleep(0.3)

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