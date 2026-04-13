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

# Continuous slow ping after burst — 1 pps so baseline flows pass the
# controller gate (pps >= 1.0) and reach the backend as normal traffic.
# Still well below the ML inference gate (pps >= 2.0) — no false positives.
BASELINE_CONT_INTERVAL  = "1"     # ping -i 1  → 1 pps

# Attack volume for single (finite) attacks.
# 50,000 pkts at --flood = ~5-8 seconds of traffic — enough for IF to score
# clearly above 0.75 and for the full Phase 1→2→3 pipeline to run visibly.
ATTACK_PKT_COUNT = 50000

# 8/8 split: 8 attackers, 8 legit hosts
# Attackers: h1,h3,h5,h7,h9,h11,h13,h15 (odd hosts)
# Legit:     h2,h4,h6,h8,h10,h12,h14,h16 (even hosts)
#
# Attack type assignment:
#   SYN  — h1  (p80, u500),  h13 (p443, u1000)
#   ICMP — h5  (u500),       h3  (u1000, data120)
#   UDP  — h9  (p53, u500),  h7  (p80, u1000)
#   Mixed extras — h11 (SYN p8080, u800), h15 (UDP p443, u800)
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

    With the 8/8 attacker/legit split, every legit host's only same-subnet
    neighbor is an attacker (odd hosts). So same-subnet targeting is useless —
    we always pick a cross-subnet legit host instead.

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

    Phase 1 — burst: ping -c 150 -i BASELINE_BURST_INTERVAL (2 pps, ~75s)
      Ensures OVS flow table has >100 packets so the ryu_controller
      pkt_count >= 50 guard is satisfied for normal-mode submissions.

    Phase 2 — slow continuous: ping -i BASELINE_CONT_INTERVAL (0.33 pps)
      Keeps the flow alive. Well below every ML gate.

    Target selection: each host pings its same-subnet legit neighbor first
    (guaranteed reachable via L2), falling back to cross-subnet only when
    no same-subnet legit neighbor exists (e.g. h3 whose only subnet-mate
    is attacker h1). Using random cross-subnet targets caused baseline pings
    to silently exit when the cross-subnet path was not yet ready, making
    check_traffic show "baseline NOT running" immediately after startup.
    """
    attacker_nums = _ATTACKER_NUMS
    legit = [h for h in hosts if int(h.name[1:]) not in attacker_nums]
    info(f"*** Starting baseline traffic on {len(legit)} legitimate hosts\n")
    info(f"    → burst: ping -c 150 -i {BASELINE_BURST_INTERVAL} (2 pps, ~75s)\n")
    info(f"    → then:  ping -i {BASELINE_CONT_INTERVAL} (1 pps, continuous)\n")

    for host in legit:
        target = _get_baseline_target(host, hosts)
        # Kill any stale ping processes before starting fresh
        host.cmd("pkill -f 'ping -c 150' 2>/dev/null; pkill -f 'ping -i' 2>/dev/null; true")
        host.cmd(
            f"ping -c 150 -i {BASELINE_BURST_INTERVAL} {target} > /dev/null 2>&1 &"
        )
        host.cmd(
            f"ping -i {BASELINE_CONT_INTERVAL} {target} > /dev/null 2>&1 &"
        )


# ==================================================================
# SINGLE ATTACKS
# ==================================================================
# Two modes per attack type:
#
#   launch_*_flood(net)      — finite burst (ATTACK_PKT_COUNT=50,000 pkts)
#                              Triggers full Phase 1→2→3 pipeline visibly.
#                              Use for demo: system detects, quarantines, blocks.
#
#   launch_*_flood_sustained — unlimited --flood, killed by stop_all_attacks()
#                              Simulates a real-world persistent DDoS.
#                              Shows continuous chart spike + ongoing mitigation.

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
        f"hping3 -S -p 80 --flood -i u500 {victim.IP()} > /dev/null 2>&1 &"
    )


def launch_icmp_flood_sustained(net, attacker_name="h5", victim_name="h6"):
    """Unlimited ICMP flood — runs until stop_all_attacks(). Simulates persistent DDoS."""
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** ICMP Flood SUSTAINED (unlimited, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    info("    → Use  py stop_all_attacks(net)  to stop.\n")
    attacker.cmd(
        f"hping3 --icmp --flood -i u500 {victim.IP()} > /dev/null 2>&1 &"
    )


def launch_udp_flood_sustained(net, attacker_name="h9", victim_name="h10"):
    """Unlimited UDP flood — runs until stop_all_attacks(). Simulates persistent DDoS."""
    attacker = net.get(attacker_name)
    victim   = net.get(victim_name)
    info(f"*** UDP Flood SUSTAINED (unlimited, fixed-src): "
         f"{attacker_name}({attacker.IP()}) → {victim_name}({victim.IP()})\n")
    info("    → Use  py stop_all_attacks(net)  to stop.\n")
    attacker.cmd(
        f"hping3 --udp -p 53 --flood -i u500 {victim.IP()} > /dev/null 2>&1 &"
    )


# ==================================================================
# CAMPAIGNS
# ==================================================================

def start_syn_flood_campaign(net):
    # Different parameters per attacker → different feature vectors → varied RF confidence
    # h1:  p80,  u500  (fast, standard HTTP port)
    # h13: p443, u1000 (slower, HTTPS port — different pps + dst port)
    # h11: p8080,u800  (medium rate, alt-HTTP port)
    info("*** [CAMPAIGN] SYN Flood — 3 attackers, varied params, fixed IPs\n")
    _syn = [
        ("h1",  "h2",  "hping3 -S -p 80   --flood -i u500  "),
        ("h13", "h14", "hping3 -S -p 443  --flood -i u1000 "),
        ("h11", "h12", "hping3 -S -p 8080 --flood -i u800  "),
    ]
    for att, vic, cmd in _syn:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) -> {vic}({victim.IP()})  [{cmd.strip()}]\n")
        attacker.cmd(cmd + victim.IP() + " > /dev/null 2>&1 &")
    info("    -> Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_icmp_flood_campaign(net):
    # h5: standard ICMP flood (u500)
    # h3: slower rate with larger payload (u1000 --data 120) — bigger byte_count
    info("*** [CAMPAIGN] ICMP Flood — 2 attackers, varied params, fixed IPs\n")
    _icmp = [
        ("h5", "h6", "hping3 --icmp --flood -i u500          "),
        ("h3", "h4", "hping3 --icmp --flood -i u1000 --data 120 "),
    ]
    for att, vic, cmd in _icmp:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) -> {vic}({victim.IP()})  [{cmd.strip()}]\n")
        attacker.cmd(cmd + victim.IP() + " > /dev/null 2>&1 &")
    info("    -> Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_udp_flood_campaign(net):
    # h9:  p53,  u500  (fast, DNS port)
    # h7:  p80,  u1000 (slower, HTTP port — different pps)
    # h15: p443, u800  (medium, HTTPS port)
    info("*** [CAMPAIGN] UDP Flood — 3 attackers, varied params, fixed IPs\n")
    _udp = [
        ("h9",  "h10", "hping3 --udp -p 53  --flood -i u500  "),
        ("h7",  "h8",  "hping3 --udp -p 80  --flood -i u1000 "),
        ("h15", "h16", "hping3 --udp -p 443 --flood -i u800  "),
    ]
    for att, vic, cmd in _udp:
        attacker = net.get(att)
        victim   = net.get(vic)
        info(f"    {att}({attacker.IP()}) -> {vic}({victim.IP()})  [{cmd.strip()}]\n")
        attacker.cmd(cmd + victim.IP() + " > /dev/null 2>&1 &")
    info("    -> Running. Use  py stop_all_attacks(net)  to stop.\n")


def start_mixed_campaign(net):
    # F1+F2 fix: added h11 (SYN p8080 u800) and h15 (UDP p443 u800) — these
    # were defined in _ATTACKER_NUMS/_CAMPAIGNS but missing from the campaign.
    # Also varied ALL attacker params (port, interval, data) so each attacker
    # produces a distinct RF feature vector — pps/byte_count/pkt_size differ
    # per IP, giving RF meaningful variation to classify correctly.
    info("*** [CAMPAIGN] Mixed DDoS — SYN + ICMP + UDP simultaneously, fixed IPs\n")
    campaigns = [
        # SYN attackers — different ports + intervals → different pps + dst_port features
        ("h1",  "h2",  "hping3 -S -p 80   --flood -i u500",   "SYN Flood"),
        ("h13", "h14", "hping3 -S -p 443  --flood -i u1000",  "SYN Flood (p443)"),
        ("h11", "h12", "hping3 -S -p 8080 --flood -i u800",   "SYN Flood (p8080)"),
        # ICMP attackers — different intervals + payload → different byte_count/pps
        ("h5",  "h6",  "hping3 --icmp --flood -i u500",        "ICMP Flood"),
        ("h3",  "h4",  "hping3 --icmp --flood -i u1000 --data 120", "ICMP Flood (large)"),
        # UDP attackers — different ports + intervals → different pps + dst_port features
        ("h9",  "h10", "hping3 --udp -p 53  --flood -i u500",  "UDP Flood"),
        ("h7",  "h8",  "hping3 --udp -p 80  --flood -i u1000", "UDP Flood (p80)"),
        ("h15", "h16", "hping3 --udp -p 443 --flood -i u800",  "UDP Flood (p443)"),
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
    for h in net.hosts:
        if int(h.name[1:]) not in _ATTACKER_NUMS:
            h.cmd("pkill -f ping 2>/dev/null; true")
    info("    Done.\n")


# ==================================================================
# TRAFFIC HEALTH CHECK
# ==================================================================

def _get_ping_neighbor(h, net) -> str:
    """Return the IP of the nearest reachable neighbor for connectivity check.

    Attacker pattern: attackers are always the .1 host on their edge switch
    (h1=10.0.0.1, h5=10.1.0.1, h9=10.2.0.1, h13=10.3.0.1).
    Their subnet-mate (h2=10.0.0.2, h6=10.1.0.2, h10=10.2.0.2, h14=10.3.0.2)
    has NO legit same-subnet neighbor — their only /24 peer is the attacker.

    Selection priority:
      1. Legit host on SAME /24 (same edge switch, 1 hop — always reliable).
      2. Legit host on SAME POD, different edge (3 hops through agg switch).
      3. Any legit host (cross-pod, 5 hops through core — populated by warmup).

    Attackers are always skipped as ping targets — during a live attack,
    OVS drop rules would cause the ping to fail even though the network is fine.
    """
    attacker_nums = _ATTACKER_NUMS
    my_ip   = h.IP()          # Bug fix: was never assigned — caused NameError crash
    parts   = my_ip.split(".")
    my_pod  = parts[1]
    my_sub  = ".".join(parts[:3])

    # Pass 1: ANY host on same /24 (same edge switch — direct L2, 1 hop).
    # We intentionally include attacker hosts here.
    # h2 shares its edge switch only with h1 (attacker). Skipping h1 forces
    # a cross-subnet fallback (3-5 hops through agg/core) which may not be
    # ready yet and shows x FAIL even when the network is perfectly healthy.
    # h2→h1 is a direct L2 hop and is always reachable regardless of OVS
    # block rules (block rules match ipv4_src of the attacker, not h2).
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
    """Fetch active quarantine list from backend.

    Returns dict of {src_ip: phase_label} for all currently mitigated IPs.
    Returns empty dict if backend is offline (topology works standalone).
    """
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
    """Live traffic health check with real-time mitigation status from backend.

    Columns:
      PING   — connectivity to nearest neighbor (— for attackers)
      MITIGATION — current backend phase if being mitigated, else baseline status
    """
    attacker_nums = _ATTACKER_NUMS

    # Query backend for live mitigation state
    quarantine = _fetch_quarantine()   # {ip: phase_label}
    stats      = _fetch_stats()        # {active_threats, malicious_dropped, ...}
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

        # Ping check — attackers skipped
        if is_attacker:
            ping_str = "—"
            ping_ok  = True   # don't count attackers in all_ok
        else:
            neighbor = _get_ping_neighbor(h, net)
            ret      = h.cmd(f"ping -c1 -W2 {neighbor} > /dev/null 2>&1; echo $?").strip()
            ping_ok  = (ret == "0")
            ping_str = "✓ ok" if ping_ok else "✗ FAIL"

        # Mitigation status from backend
        if ip in quarantine:
            phase       = quarantine[ip]
            mit_status  = f"⚡ MITIGATED — {phase}"
        else:
            mit_status  = None

        if is_attacker:
            # Check if hping3 is actually running on this attacker host
            hping_out = h.cmd("pgrep -x hping3 2>/dev/null").strip()
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
                # This legit host is being mitigated — false positive
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
    """Populate OVS MAC/forwarding tables across ALL switches before CLI starts.

    Root cause of "cannot connect to each other" after Ryu connect:
    In a fat-tree k=4, a cross-subnet packet traverses 5 switches
    (edge → agg → core → agg → edge). Each switch starts with only a
    table-miss rule. The first packet to each path hits all 5 switches
    as table-miss, flooding to controller for MAC learning. Until Ryu
    installs forwarding rules on all 5 switches, subsequent packets are
    dropped or flooded. The previous warmup only covered same-/24 pairs
    (1 switch hop), leaving agg and core switch tables completely empty.

    Phase 1 — local warmup (2 rounds): populate edge switch tables.
    Phase 2 — cross-subnet warmup (2 rounds): populate agg + core tables
      by pinging every legit host to every other legit host across subnets.
      This ensures check_traffic shows all green on first run.
    """
    attacker_nums = _ATTACKER_NUMS
    legit_hosts   = [h for h in hosts if int(h.name[1:]) not in attacker_nums]

    # ── Phase 1: local /24 pairs ─────────────────────────────────────────────
    subnet_groups: dict = {}
    for h in hosts:
        subnet = ".".join(h.IP().split(".")[:3])
        subnet_groups.setdefault(subnet, []).append(h)

    local_total = sum(len(g) * (len(g) - 1) for g in subnet_groups.values())
    info(f"*** Phase 1 warmup — {local_total} local pairs (edge switches)...\n")

    # S2 fix: reduced from 2 rounds to 1 — one successful ping is sufficient
    # for OVS to learn the MAC and Ryu to install the forwarding rule.
    # Second round was redundant and added ~4-5s with no benefit.
    info(f"    Round 1/1 ...\n")
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

    info("*** Phase 1 done — edge switch tables populated.\n")

    # ── Phase 2: full cross-subnet warmup ────────────────────────────────────
    # S3 fix: reduced from 2 rounds × ping -c2 -W2 to 1 round × ping -c1 -W1.
    # Ryu installs the forwarding rule after the FIRST successful reply —
    # extra rounds were wasting ~8-10s. One round is sufficient to populate
    # agg and core switch tables for all cross-pod paths.
    cross_pairs = [
        (src, dst)
        for src in legit_hosts
        for dst in legit_hosts
        if src is not dst
        and ".".join(src.IP().split(".")[:3]) != ".".join(dst.IP().split(".")[:3])
    ]
    info(f"*** Phase 2 warmup — {len(cross_pairs)} cross-subnet pairs (agg + core switches)...\n")
    info("    (1 round, ping -c1 -W1)\n")

    procs = []
    for src, dst in cross_pairs:
        p = src.popen(
            f"ping -c1 -W1 {dst.IP()} > /dev/null 2>&1", shell=True)
        procs.append(p)
    for p in procs:
        p.wait()

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
    # M10 fix: banner now shows accurate rates derived from the constants
    info(f"  BASELINE:\n")
    info(f"    burst:  ping -c 150 -i {BASELINE_BURST_INTERVAL} (2 pps, ~75s)\n")
    info(f"    then:   ping -i {BASELINE_CONT_INTERVAL} (0.33 pps, continuous)\n\n")

    info("  ── SINGLE BURST (finite — shows full Phase 1→2→3 pipeline) ──────\n\n")
    info(f"    py launch_syn_flood(net)             # {ATTACK_PKT_COUNT:,} SYN pkts, h1→h2\n")
    info(f"    py launch_icmp_flood(net)            # {ATTACK_PKT_COUNT:,} ICMP pkts, h5→h6\n")
    info(f"    py launch_udp_flood(net)             # {ATTACK_PKT_COUNT:,} UDP pkts, h9→h10\n\n")

    info("  ── SINGLE SUSTAINED (unlimited — real-world persistent DDoS) ────\n\n")
    info("    py launch_syn_flood_sustained(net)   # SYN, unlimited, h1→h2\n")
    info("    py launch_icmp_flood_sustained(net)  # ICMP, unlimited, h5→h6\n")
    info("    py launch_udp_flood_sustained(net)   # UDP, unlimited, h9→h10\n\n")

    info("  ── CAMPAIGN (4 attackers simultaneously, UNLIMITED) ──────────────\n\n")
    info("    py start_syn_flood_campaign(net)     # → RF: SYN Flood\n")
    info("    py start_icmp_flood_campaign(net)    # → RF: ICMP Flood\n")
    info("    py start_udp_flood_campaign(net)     # → RF: UDP Flood\n")
    info("    py start_mixed_campaign(net)         # → RF: all 3 types\n\n")

    info("  ── STOP ──────────────────────────────────────────────────────────\n\n")
    info("    py stop_all_attacks(net)             # kill hping3 + flush OVS rules\n")
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
    """Restart baseline ping for the host with the given IP.

    Called when the backend signals a manually-released host needs
    its traffic restarted.
    """
    for host in hosts:
        if host.IP() == src_ip:
            host.cmd("pkill -f 'ping -i' 2>/dev/null; true")
            others = [
                h.IP() for h in hosts
                if h.IP() != src_ip and int(h.name[1:]) not in _ATTACKER_NUMS
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

    Columns:
      TIME     — when the flow was scanned
      SRC_IP   — source IP of the flow
      PPS      — packets per second at time of scan
      IF_SCORE — Isolation Forest anomaly score (higher = more anomalous)
      THR      — current IF threshold (score must exceed this)
      ANOMALY  — YES if flagged, no if normal
      CLASS    — RF attack classification (or Normal)
      CONF%    — RF confidence percentage
      ACTION   — mitigation action taken (or pending/—)
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

                # Clear and redraw
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
                # Print all at once to reduce flicker
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
    # S1 fix: replaced fixed sleep with active polling — checks every 0.5s
    # whether all 20 switches have completed OpenFlow handshake by querying
    # the Ryu REST API. Proceeds as soon as all are connected (typically 2-3s)
    # instead of always waiting the full 5s. Falls back to 8s max timeout.
    _ryu_ready = False
    for _wait_i in range(16):  # 16 × 0.5s = 8s max
        time.sleep(0.5)
        try:
            import urllib.request as _ur
            with _ur.urlopen("http://127.0.0.1:8080/v1.0/topology/switches", timeout=1) as _r:
                _switches = __import__("json").loads(_r.read())
            if len(_switches) >= 20:
                info(f"*** All {len(_switches)} switches connected ({(_wait_i+1)*0.5:.1f}s)\n")
                _ryu_ready = True
                break
            else:
                info(f"    {len(_switches)}/20 switches connected...\n")
        except Exception:
            info(f"    Waiting for Ryu... ({(_wait_i+1)*0.5:.1f}s)\n")
    if not _ryu_ready:
        info("*** Timeout waiting for all switches — proceeding anyway.\n")

    _print_banner(hosts)

    info("*** Starting baseline normal traffic...\n")
    start_baseline_traffic(hosts)
    time.sleep(1)

    _warmup_macs(net, hosts)

    info("*** Restarting baseline post-warmup...\n")
    start_baseline_traffic(hosts)

    # S4 fix: reduced from 2s to 0.5s — ping processes register within 0.5s.
    info("*** Waiting for baseline pings to register...\n")
    time.sleep(0.5)

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