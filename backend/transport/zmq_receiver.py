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

# ── Raw traffic counters (for live chart) ─────────────────────────────────────
# These count NEW packets per poll interval, not cumulative totals.
# OVS flow stats return cumulative packet_count — we must track the last-seen
# value per flow and only add the DELTA to avoid massively overcounting.
_raw_lock        = threading.Lock()
_raw_total_pkts  = 0
_raw_normal_pkts = 0
_raw_attack_pkts = 0

# Last-seen cumulative packet_count per flow key: (src_ip, dpid) → int
# Flows are identified by src_ip+dpid since that's all zmq_receiver sees.
# Reset on reconnect (Ryu restart resets OVS counters to 0 anyway).
_flow_prev_pkts: dict[tuple, int] = {}
_flow_lock = threading.Lock()


def get_raw_counts() -> dict:
    with _raw_lock:
        return {
            "raw_total":  _raw_total_pkts,
            "raw_normal": _raw_normal_pkts,
            "raw_attack": _raw_attack_pkts,
        }


def _reset_flow_state() -> None:
    """Called on ZMQ reconnect — OVS counters reset when Ryu restarts."""
    with _flow_lock:
        _flow_prev_pkts.clear()
    log.info("ZMQ receiver: flow delta state reset")


def _parse_and_route(raw: bytes) -> None:
    global _raw_total_pkts, _raw_normal_pkts, _raw_attack_pkts

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

        # ── Compute delta packets since last poll ─────────────────────────────
        # OVS packet_count is cumulative — adding it directly inflates the chart
        # by recounting every existing packet on every poll.
        # Example: flow has 50,000 pkts at poll 1, 50,100 at poll 2.
        # We should add 100 (new packets), not 50,100 (cumulative).
        flow_key = (src_ip, dpid)
        with _flow_lock:
            prev_count     = _flow_prev_pkts.get(flow_key, 0)
            delta_pkts     = max(pkt_count_cumulative - prev_count, 0)
            _flow_prev_pkts[flow_key] = pkt_count_cumulative

        if delta_pkts == 0:
            # No new packets since last poll — nothing to count or route
            return

        # Gate: only submit to ML pipeline if flow is genuinely high-rate.
        # MIN_FLOW_PKTS=1 so rand-source attack IPs (appear once) are caught.
        # MIN_PPS=20 matches worker.py gate — no point submitting what worker rejects.
        # Real floods: >>100 pps. Baseline ping -i 0.5 = 2 pps. pingall ≈ 0 pps.
        MIN_FLOW_PKTS = 1
        MIN_PPS       = 20.0
        crosses_threshold = (pkt_count_cumulative >= MIN_FLOW_PKTS and pps >= MIN_PPS)

        # ── Update raw counters ───────────────────────────────────────────────
        # IMPORTANT: raw_attack/raw_normal are used by the graph and cards.
        # crosses_threshold here just means "submitted to ML" — the actual
        # attack/normal classification is done by worker + decision_engine.
        # So we count ALL traffic as normal here; decision_engine increments
        # malicious_dropped when it actually confirms an attack.
        with _raw_lock:
            _raw_total_pkts  += delta_pkts
            _raw_normal_pkts += delta_pkts   # assume normal; DE corrects if attack

        if crosses_threshold:
            worker.submit(src_ip, flow_stats, switch_stats)
        else:
            # Sub-threshold = confirmed normal traffic
            try:
                from backend.database import writer
                writer.log_traffic_summary(total=1, threats=0, true_neg=1, fp=0)
            except Exception:
                pass


def _receiver_loop() -> None:
    global _raw_total_pkts, _raw_normal_pkts, _raw_attack_pkts

    ctx = zmq.Context.instance()

    while True:
        sock = ctx.socket(zmq.PULL)
        sock.setsockopt(zmq.RCVTIMEO, _RECV_TIMEOUT_MS)
        sock.setsockopt(zmq.LINGER, 0)

        try:
            sock.connect(ZMQ_TELEMETRY_ADDR)
            log.info("ZMQ receiver connected to %s", ZMQ_TELEMETRY_ADDR)

            # Reset delta state — Ryu restart means OVS counters reset to 0
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