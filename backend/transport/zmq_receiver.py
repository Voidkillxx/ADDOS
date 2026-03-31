import zmq
import json
import time
import threading
import logging
from backend.config import ZMQ_TELEMETRY_ADDR
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

# Last-seen cumulative packet_count per flow key: (src_ip, dpid) → int
_flow_prev_pkts: dict[tuple, int] = {}
_flow_lock = threading.Lock()


def get_raw_counts() -> dict:
    with _raw_lock:
        return {"raw_total": _raw_total_pkts}


def _reset_flow_state() -> None:
    """Called on ZMQ reconnect — OVS counters reset when Ryu restarts."""
    with _flow_lock:
        _flow_prev_pkts.clear()
    log.info("ZMQ receiver: flow delta state reset")


def _parse_and_route(raw: bytes) -> None:
    global _raw_total_pkts

    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return

    msg_type = msg.get("type")

    if msg_type == "packet_in":
        src_ip = msg.get("src_ip", "")
        proto  = msg.get("proto", "")

        if proto == "TCP" and msg.get("tcp_flags_syn") and not msg.get("tcp_flags_ack"):
            syn_filter.on_syn(src_ip)
        elif proto == "TCP" and msg.get("tcp_flags_ack"):
            syn_filter.on_ack(src_ip)

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

        if delta_pkts == 0:
            return

        MIN_FLOW_PKTS = 1
        MIN_PPS       = 20.0

        # Bug 2 fix: rand-source flood flows have pkt_count=1 and short duration.
        # Their computed pps = 1/duration_sec which can be < 20 → filtered.
        # During a flood (switch_delta_pps >= 80), bypass MIN_PPS entirely.
        # switch_delta_pps is now correctly boosted by rate_pkt_in in ryu_controller
        # (Bug 1 fix) so this flag is reliable even with throttled flows.
        switch_delta_pps = float(flow_stats.get("switch_delta_pps", 0.0))
        is_flood_mode    = switch_delta_pps >= 80.0

        crosses_threshold = (
            pkt_count_cumulative >= MIN_FLOW_PKTS
            and (pps >= MIN_PPS or is_flood_mode)
        )

        with _raw_lock:
            _raw_total_pkts += delta_pkts

        if crosses_threshold:
            worker.submit(src_ip, flow_stats, switch_stats)
        else:
            try:
                from backend.database import writer
                writer.log_traffic_summary(total=1, threats=0, true_neg=1, fp=0)
            except Exception:
                pass


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