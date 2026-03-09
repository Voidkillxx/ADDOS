# Must be first — patches stdlib before eventlet/gevent touches anything
import eventlet
eventlet.monkey_patch()

import json
import time
import collections

import zmq
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp, udp
from ryu.lib import hub

TELEMETRY_ADDR = "tcp://127.0.0.1:5555"
COMMAND_ADDR   = "tcp://127.0.0.1:5556"
STATS_INTERVAL = 2.0   # 2s reduces ZMQ overload during rand-source floods


class FatTreeController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._zmq_ctx  = zmq.Context()

        # Telemetry PUSH socket → Backend PULL
        self._tel_sock = self._zmq_ctx.socket(zmq.PUSH)
        self._tel_sock.setsockopt(zmq.SNDHWM, 5000)  # large enough for rand-source flood bursts
        self._tel_sock.setsockopt(zmq.LINGER, 0)
        self._tel_sock.bind(TELEMETRY_ADDR)

        # Command PULL socket ← Backend PUSH
        self._cmd_sock = self._zmq_ctx.socket(zmq.PULL)
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 500)
        self._cmd_sock.setsockopt(zmq.LINGER, 0)
        self._cmd_sock.bind(COMMAND_ADDR)

        # Per-switch state
        self._datapaths: dict  = {}
        self._mac_to_port: dict = collections.defaultdict(dict)

        # Switch-level delta tracking — key: dpid → (last_total_pkts, is_initialized)
        # is_initialized=False on first poll so we skip the cold-start spike
        self._switch_prev_total: dict[int, tuple] = {}

        # Per-switch aggregated counters (updated each FlowStats reply)
        self._switch_agg: dict = collections.defaultdict(lambda: {
            "disp_pakt": 0, "disp_byte": 0, "gfe": 0,
            "g_usip": set(), "rfip": set(),
            "avg_durat": 0.0, "avg_flow_dst": 0,
            "last_reply_ts": None, "disp_interval": 1.0,
        })

        # PacketIn counters per switch (reset each poll cycle)
        self._pkt_in_count: dict = collections.defaultdict(int)
        self._pkt_in_ts:    dict = {}

        # Active port counts from PortStats
        self._port_counts: dict = collections.defaultdict(int)

        hub.spawn(self._stats_poll_loop)
        hub.spawn(self._command_listener)

    # ------------------------------------------------------------------
    # OpenFlow handshake
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp       = ev.msg.datapath
        ofp      = dp.ofproto
        parser   = dp.ofproto_parser
        self._datapaths[dp.id] = dp
        self.logger.info(
            '✔ Switch CONNECTED  dpid=%016x  (%d/%d switches)',
            dp.id, len(self._datapaths), 20
        )

        # Table-miss: send to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(datapath=dp, priority=0,
                                 match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnect_handler(self, ev):
        dp   = ev.datapath
        dpid = dp.id  # can be None if switch disconnects before handshake
        self._datapaths.pop(dpid, None)
        self._switch_agg.pop(dpid, None)
        self._pkt_in_count.pop(dpid, None)
        self._port_counts.pop(dpid, None)
        self.logger.info(
            '✘ Switch DISCONNECTED  dpid=%s  (%d switches remaining)',
            ('%016x' % dpid) if dpid is not None else 'unknown',
            len(self._datapaths)
        )

    # ------------------------------------------------------------------
    # PacketIn
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg  = ev.msg
        dp   = msg.datapath
        ofp  = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        pkt  = packet.Packet(msg.data)
        eth  = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return

        src_ip = ip4.src
        dst_ip = ip4.dst

        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        proto        = "TCP" if tcp_pkt else ("ICMP" if icmp_pkt else ("UDP" if udp_pkt else "OTHER"))
        tcp_flags_syn = bool(tcp_pkt and (tcp_pkt.bits & 0x02))
        tcp_flags_ack = bool(tcp_pkt and (tcp_pkt.bits & 0x10))

        self._pkt_in_count[dpid] += 1

        # Forward telemetry
        self._push({
            "type":          "packet_in",
            "dpid":          dpid,
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "proto":         proto,
            "tcp_flags_syn": tcp_flags_syn,
            "tcp_flags_ack": tcp_flags_ack,
            "ts":            time.time(),
        })

        # Basic L2 learning + forwarding (no ML logic here)
        in_port = msg.match["in_port"]
        self._mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self._mac_to_port[dpid]:
            out_port = self._mac_to_port[dpid][eth.dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow rule so subsequent packets bypass the controller.
        # IMPORTANT: for IPv4 packets we include eth_type + ipv4_src in the
        # match so that OFPFlowStatsReply entries carry the src IP — without
        # this the flow_stats telemetry loop skips every entry and the backend
        # never sees any traffic data.
        if out_port != ofp.OFPP_FLOOD:
            if ip4:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    eth_dst=eth.dst,
                )
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)

            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=1,
                    idle_timeout=60, hard_timeout=0,    # matches sdn_collector FLOW_IDLE_TIMEOUT=60
                    buffer_id=msg.buffer_id,
                    match=match, instructions=inst)
                dp.send_msg(mod)
                return   # buffer already consumed by flow mod
            else:
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=1,
                    idle_timeout=60, hard_timeout=0,    # matches sdn_collector FLOW_IDLE_TIMEOUT=60
                    match=match, instructions=inst)
                dp.send_msg(mod)

        # Send the current packet out
        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=None)
        else:
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)

    # ------------------------------------------------------------------
    # FlowStats reply
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid  = ev.msg.datapath.id
        body  = ev.msg.body
        now   = time.time()

        agg = self._switch_agg[dpid]
        prev_ts = agg["last_reply_ts"]
        interval = (now - prev_ts) if prev_ts else 1.0
        agg["last_reply_ts"]  = now
        agg["disp_interval"]  = max(interval, 0.001)

        total_pkt  = 0
        total_byte = 0
        durations  = []
        dst_ips    = set()
        src_ips    = set()

        # ── Switch-level delta pps for flood gate ─────────────────────────────
        # Cold-start fix: on first poll, _sw_prev=0 but flows already have
        # accumulated baseline packets → delta is artificially huge (900+ pps).
        # We skip the gate on the first poll per switch (is_initialized=False).
        _sw_total_now = sum(s.packet_count for s in body)
        _prev_entry   = self._switch_prev_total.get(dpid)
        if _prev_entry is None:
            # First poll — record baseline, mark as cold start, skip gate
            self._switch_prev_total[dpid] = (_sw_total_now, False)
            agg["switch_delta_pps"] = 0.0
        else:
            _sw_prev, _initialized = _prev_entry
            if not _initialized:
                # Second poll — now we have a valid baseline to diff against
                self._switch_prev_total[dpid] = (_sw_total_now, True)
                agg["switch_delta_pps"] = 0.0
            else:
                _sw_delta = max(_sw_total_now - _sw_prev, 0)
                self._switch_prev_total[dpid] = (_sw_total_now, True)
                agg["switch_delta_pps"] = _sw_delta / max(interval, 0.1)

        for stat in body:
            total_pkt  += stat.packet_count
            total_byte += stat.byte_count
            dur_us = stat.duration_sec * 1e6 + stat.duration_nsec / 1000
            durations.append(dur_us)

            match = stat.match
            if "ipv4_src" in match:
                src_ips.add(match["ipv4_src"])
            if "ipv4_dst" in match:
                dst_ips.add(match["ipv4_dst"])

            # Per-flow telemetry for IF feature extraction
            # ── CRITICAL: must match sdn_collector_controller.py exactly ──────
            # Collector uses full float duration (sec + nsec/1e9) as denominator.
            # Old code used max(dur_sec, 0.001) → for new flows with dur_sec=0,
            # this gave pps = pkt_cnt/0.001 = up to 500x the training value,
            # blowing the feature completely out of the scaler's fitted range.
            _total_s = stat.duration_sec + stat.duration_nsec / 1e9
            _total_s = max(_total_s, 1e-9)
            pps  = stat.packet_count / _total_s   # matches collector: pkt_cnt/total
            bps  = stat.byte_count   / _total_s   # matches collector: byt_cnt/total
            ppns = pps / 1e9                       # matches collector: pps/1e9
            bpns = bps / 1e9                       # matches collector: bps/1e9

            src_ip = match.get("ipv4_src")
            # Skip table-miss/non-IP flows — no src IP or default 0.0.0.0 wildcard
            if not src_ip or src_ip == "0.0.0.0":
                continue

            # Guard: skip flows that look like normal low-rate traffic.
            #
            # Two conditions must BOTH be true to send to IF:
            #   1. Total packet count >= 50  (rules out short ping bursts)
            #   2. Packets-per-second >= 10  (rules out long-lived low-rate flows
            #      e.g. baseline ping -i2 = 0.5 pps, warmup ping -c1 = tiny pps)
            #
            # A real flood attack: 10,000 pkts in <5s → pps >> 100, count >> 50.
            # Baseline ping -i2 over 60s: count=30, pps=0.5  → SKIP (count<50)
            # Warmup ping after 60s poll: count=60, pps=1.0  → SKIP (pps<10)
            # Now that pps uses correct full-duration denominator (matching collector),
            # values are no longer inflated. Keep pkt threshold but lower pps guard
            # since cumulative-avg pps for real attacks is still >> 10.
            # ── Flood gate using switch-level delta pps ──────────────────
            # Rand-source floods: each IP has 1 pkt → per-flow pps=0.5 → missed.
            # Switch delta sees all flows: 3000 rand-pkts/2s → delta_pps=1500.
            # Threshold 500 safely separates:
            #   Real flood:      3000+ pps per attacker → switch delta >> 500
            #   Baseline (12 hosts × 2 pps = 24 pps): switch delta << 500
            #   Cold start skipped above (first 2 polls → delta=0)
            switch_delta_pps = agg.get("switch_delta_pps", 0.0)
            is_flood_switch  = switch_delta_pps >= 500.0

            if is_flood_switch:
                # Flood mode: submit every flow with >= 1 pkt (catches rand-source)
                if stat.packet_count < 1:
                    continue
            else:
                # Normal mode: only submit high-rate individual flows
                if stat.packet_count < 50 or pps < 5.0:
                    continue

            self._push({
                "type":       "flow_stats",
                "dpid":       dpid,
                "src_ip":     src_ip,
                "flow_stats": {
                    "flow_duration_sec":        stat.duration_sec,
                    "flow_duration_nsec":       stat.duration_nsec,
                    "idle_timeout":             stat.idle_timeout,
                    "hard_timeout":             stat.hard_timeout,
                    "flags":                    stat.flags,
                    "packet_count":             stat.packet_count,
                    "byte_count":               stat.byte_count,
                    "packet_count_per_second":  pps,
                    "packet_count_per_nsecond": ppns,
                    "byte_count_per_second":    bps,
                    "byte_count_per_nsecond":   bpns,
                    "switch_delta_pps":         switch_delta_pps,
                },
                "switch_stats": self._build_switch_stats(dpid),
            })

        n_flows = max(len(body), 1)
        agg["disp_pakt"]    = total_pkt
        agg["disp_byte"]    = total_byte
        agg["gfe"]          = n_flows
        agg["g_usip"]       = src_ips
        agg["avg_flow_dst"] = len(dst_ips)
        agg["avg_durat"]    = (sum(durations) / n_flows) if durations else 0.0

        rate_pkt_in = self._pkt_in_count.get(dpid, 0) / interval
        self._pkt_in_count[dpid] = 0

        agg["rate_pkt_in"] = rate_pkt_in

    # ------------------------------------------------------------------
    # PortStats reply
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        # Count ports with at least 1 rx packet as active
        active = sum(1 for p in ev.msg.body if p.rx_packets > 0)
        self._port_counts[dpid] = active

    # ------------------------------------------------------------------
    # Stats polling loop
    # ------------------------------------------------------------------

    def _stats_poll_loop(self):
        while True:
            hub.sleep(STATS_INTERVAL)
            for dpid, dp in list(self._datapaths.items()):
                self._request_flow_stats(dp)
                self._request_port_stats(dp)

    def _request_flow_stats(self, dp):
        parser = dp.ofproto_parser
        req    = parser.OFPFlowStatsRequest(dp)
        dp.send_msg(req)

    def _request_port_stats(self, dp):
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        req    = parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
        dp.send_msg(req)

    # ------------------------------------------------------------------
    # Command listener — applies OpenFlow rules from backend
    # ------------------------------------------------------------------

    def _command_listener(self):
        # Use NOBLOCK + hub.sleep so Ryu's gevent hub is not starved
        # by a blocking recv() call
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 0)   # non-blocking
        while True:
            try:
                raw = self._cmd_sock.recv(zmq.NOBLOCK)
                cmd = json.loads(raw)
                self._apply_command(cmd)
            except zmq.Again:
                hub.sleep(0.05)   # yield to gevent scheduler, retry in 50ms
            except Exception as e:
                self.logger.warning("Command error: %s", e)
                hub.sleep(0.05)

    def _apply_command(self, cmd: dict):
        action   = cmd.get("action")
        src_ip   = cmd.get("src_ip")

        for dpid, dp in list(self._datapaths.items()):
            parser = dp.ofproto_parser
            ofp    = dp.ofproto

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

            if action == "block":
                # Permanent drop rule — high priority, no idle timeout
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=100,
                    idle_timeout=0, hard_timeout=0,
                    match=match, instructions=[])
                dp.send_msg(mod)

            elif action == "quarantine":
                # Short-lived drop to pause traffic during analysis
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=90,
                    idle_timeout=35, hard_timeout=35,
                    match=match, instructions=[])
                dp.send_msg(mod)

            elif action == "rate_limit":
                # Meter-based rate limit — drop at priority 80
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=80,
                    idle_timeout=70, hard_timeout=70,
                    match=match, instructions=[])
                dp.send_msg(mod)

            elif action == "clear":
                # Delete all rules for this src_ip
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    match=match)
                dp.send_msg(mod)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_switch_stats(self, dpid: int) -> dict:
        agg  = self._switch_agg[dpid]
        n    = max(agg["gfe"], 1)
        return {
            "disp_pakt":     agg["disp_pakt"],
            "disp_byte":     agg["disp_byte"],
            "mean_pkt":      agg["disp_pakt"] / n,
            "mean_byte":     agg["disp_byte"] / n,
            "avg_durat":     agg["avg_durat"],       # µs
            "avg_flow_dst":  agg["avg_flow_dst"],
            "rate_pkt_in":   agg.get("rate_pkt_in", 0),
            "disp_interval": agg["disp_interval"],
            "gfe":           agg["gfe"],
            "g_usip":        len(agg["g_usip"]),
            "rfip":          self._count_rfip(dpid),
            "gsp":           self._port_counts.get(dpid, 0),
        }

    def _count_rfip(self, dpid: int) -> int:
        """Count dst IPs outside the local /24 subnet of this switch."""
        import ipaddress
        agg = self._switch_agg[dpid]
        # Use the first known src IP as a proxy for the switch subnet
        sample = next(iter(agg["g_usip"]), None)
        if not sample:
            return 0
        try:
            local_net = ipaddress.ip_network(f"{sample}/24", strict=False)
        except ValueError:
            return 0
        # rfip = dst IPs outside local /24 — approximated from flow match data
        # This is computed in build_switch_stats via g_usip heuristic
        return max(0, agg["avg_flow_dst"] - 1)

    def _push(self, msg: dict) -> None:
        try:
            self._tel_sock.send_json(msg, zmq.NOBLOCK)
        except zmq.Again:
            pass   # drop if backend is not connected