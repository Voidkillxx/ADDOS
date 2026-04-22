import zmq
import json
import time
import threading
import logging
from backend.config import ZMQ_TELEMETRY_ADDR, SYN_HALFOPEN_LIMIT
from backend.pipeline import worker
from backend.pipeline.syn_prefilter import syn_filter

log = logging.getLogger(__name__)

_RECONNECT_DELAY_S = 3.0
_RECV_TIMEOUT_MS   = 1000

# ── Raw traffic counter (for live chart and Normal Traffic card) ───────────────
# C2 fix: _raw_normal_pkts and _raw_attack_pkts have been removed.
# Previously _raw_normal_pkts was set to delta_pkts for ALL traffic with a
# comment saying "DE corrects if attack" — but that correction was never
# implemented, making Normal Traffic always equal Total Traffic (visible in
# both screenshots: 6,435,747 = 6,435,747 and 11,184,390 = 11,184,390).
# _raw_attack_pkts was declared but written to nowhere — always 0.
#
# Replacement (Option A, approved): stats.py computes
#   normal_packets = max(raw_total − malicious_dropped, 0)
# malicious_dropped comes from decision_engine (incremented only when RF
# confirms a real attack), giving a meaningful and accurate normal count.
_raw_lock       = threading.Lock()
_raw_total_pkts = 0

# Fix B: track connected switch count from ZMQ switch_count messages.
# topology.py polls get_switch_count() every 0.5s to know when all 20
# switches are connected without needing the Ryu REST topology API.
_switch_count_lock = threading.Lock()
_connected_switches = 0

# Last-seen cumulative packet_count per flow key: (src_ip, dpid) → int
_flow_prev_pkts: dict[tuple, int] = {}
_flow_lock = threading.Lock()


def get_raw_counts() -> dict:
    with _raw_lock:
        return {"raw_total": _raw_total_pkts}


def get_switch_count() -> int:
    """Returns the number of switches currently connected to Ryu.
    Updated via ZMQ switch_count messages — no REST API needed.
    Called by topology.py during startup polling (Fix B).
    """
    with _switch_count_lock:
        return _connected_switches


def _reset_flow_state() -> None:
    """Called on ZMQ reconnect — OVS counters reset when Ryu restarts.
    Also resets _raw_total_pkts so cumulative OVS counts are not
    double-counted after reconnect (fix for billion-packet UI bug).
    """
    global _raw_total_pkts
    with _flow_lock:
        _flow_prev_pkts.clear()
    with _raw_lock:
        _raw_total_pkts = 0
    log.info("ZMQ receiver: flow delta state reset (raw_total reset to 0)")


def _parse_and_route(raw: bytes) -> None:
    global _raw_total_pkts

    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    msg_type = msg.get("type")

    if msg_type == "switch_count":
        # Fix B: update connected switch count so topology.py can poll
        # get_switch_count() instead of hitting the 404 REST endpoint.
        global _connected_switches
        with _switch_count_lock:
            _connected_switches = int(msg.get("connected", 0))
        return

    elif msg_type == "packet_in":
        src_ip = msg.get("src_ip", "")
        proto  = msg.get("proto", "")

        if proto == "TCP" and msg.get("tcp_flags_syn") and not msg.get("tcp_flags_ack"):
            flagged = syn_filter.on_syn(src_ip)
            # Bug 4 fix: when SYN prefilter trips, submit directly to the worker
            # so the IP reaches the decision engine and appears in the audit log.
            # Previously on_syn() return value was ignored — SYN floods never
            # reached the pipeline and were invisible in the dashboard.
            if flagged:
                syn_flow_stats = {
                    "packet_count":            SYN_HALFOPEN_LIMIT,
                    "packet_count_per_second":  float(SYN_HALFOPEN_LIMIT),
                    "switch_delta_pps":         float(SYN_HALFOPEN_LIMIT),
                    "ip_proto":                 6,
                    "src_port":                 0,
                    "dst_port":                 80,
                    "byte_count":               SYN_HALFOPEN_LIMIT * 60,
                }
                worker.submit(src_ip, syn_flow_stats, {})
                log.info("SYN prefilter tripped for %s — submitted to pipeline", src_ip)
        elif proto == "TCP" and msg.get("tcp_flags_ack"):
            syn_filter.on_ack(src_ip)

    elif msg_type == "dropped_delta":
        # F3 fix: real physical packet drop count from OVS blocked flow entries.
        # ryu_controller sends this for every priority 80/90/100 flow entry
        # (rate_limit / quarantine / block rules) each FlowStats poll interval.
        # Accumulate into decision_engine so UI shows true malicious_dropped.
        src_ip = msg.get("src_ip", "")
        delta  = int(msg.get("delta", 0))
        if src_ip and delta > 0:
            try:
                from backend.pipeline.decision_engine import record_dropped_packets
                record_dropped_packets(src_ip, delta)
            except Exception:
                pass

    elif msg_type == "flow_stats":
        src_ip       = msg.get("src_ip", "")
        flow_stats   = msg.get("flow_stats", {})
        switch_stats = msg.get("switch_stats", {})
        dpid         = msg.get("dpid", 0)

        if not src_ip or not flow_stats:
            return

        pkt_count_cumulative = int(flow_stats.get("packet_count", 0))
        pps                  = float(flow_stats.get("packet_count_per_second", 0.0))

        # Delta tracking — OVS packet_count is cumulative
        flow_key = (src_ip, dpid)
        with _flow_lock:
            prev_count                = _flow_prev_pkts.get(flow_key, 0)
            delta_pkts                = max(pkt_count_cumulative - prev_count, 0)
            _flow_prev_pkts[flow_key] = pkt_count_cumulative

        # delta=0 check removed — submit anyway so ip_proto reaches RF
        # worker guards against zero-packet flows internally

        # Lowered MIN_PPS 2.0→0.5 so early-stage ICMP/UDP flows (which build
        # up slowly in OVS) reach the worker before pps is fully elevated.
        MIN_PPS          = 0.5
        switch_delta_pps = float(flow_stats.get("switch_delta_pps", 0.0))
        is_flood_mode    = switch_delta_pps >= 1.0  # match worker/ryu flood gate

        crosses_threshold = (
            pkt_count_cumulative >= 1
            and (pps >= MIN_PPS or is_flood_mode)
        )

        with _raw_lock:
            _raw_total_pkts += delta_pkts

        if crosses_threshold:
            # Skip ML pipeline for IPs already in Phase 2/3 (Time Ban/Blackhole).
            # OVS block rule is already in place — running IF/RF again wastes CPU
            # and risks flipping the attack vector (fixed in state_machine too).
            try:
                from backend.mitigation.state_machine import state_machine as _sm
                _ip_state = _sm._states.get(src_ip)
                if _ip_state is not None and _ip_state.phase >= 2:
                    return
            except Exception:
                pass
            worker.submit(src_ip, flow_stats, switch_stats)


def _receiver_loop() -> None:
    global _raw_total_pkts

    ctx = zmq.Context.instance()

    while True:
        sock = ctx.socket(zmq.PULL)
        sock.setsockopt(zmq.RCVTIMEO, _RECV_TIMEOUT_MS)
        sock.setsockopt(zmq.LINGER, 0)

        try:
            sock.connect(ZMQ_TELEMETRY_ADDR)
            log.info("ZMQ receiver connected to %s", ZMQ_TELEMETRY_ADDR)
            _reset_flow_state()

            while True:
                try:
                    raw = sock.recv()
                    _parse_and_route(raw)
                except zmq.Again:
                    pass
                except zmq.ZMQError as e:
                    log.warning("ZMQ recv error: %s — reconnecting", e)
                    break

        except zmq.ZMQError as e:
            log.warning("ZMQ connect failed: %s — retry in %ss", e, _RECONNECT_DELAY_S)
        finally:
            sock.close()

        time.sleep(_RECONNECT_DELAY_S)


def start() -> None:
    t = threading.Thread(target=_receiver_loop, name="zmq-receiver", daemon=True)
    t.start()
    log.info("ZMQ receiver thread started (addr=%s)", ZMQ_TELEMETRY_ADDR)