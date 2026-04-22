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
STATS_INTERVAL = 1.0  # Balanced: fast enough for demo, light enough for VMware


class FatTreeController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._zmq_ctx  = zmq.Context()

        self._tel_sock = self._zmq_ctx.socket(zmq.PUSH)
        self._tel_sock.setsockopt(zmq.SNDHWM, 5000)
        self._tel_sock.setsockopt(zmq.LINGER, 0)
        self._tel_sock.bind(TELEMETRY_ADDR)

        self._cmd_sock = self._zmq_ctx.socket(zmq.PULL)
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 500)
        self._cmd_sock.setsockopt(zmq.LINGER, 0)
        self._cmd_sock.bind(COMMAND_ADDR)

        self._datapaths: dict   = {}
        self._mac_to_port: dict = collections.defaultdict(dict)

        # Fix B: shared switch count — written on connect/disconnect,
        # read by the backend /api/switches endpoint so topology.py
        # can poll it without needing Ryu's REST topology app.
        FatTreeController._connected_count = 0

        self._switch_prev_total: dict[int, tuple] = {}

        self._switch_agg: dict = collections.defaultdict(lambda: {
            "disp_pakt": 0, "disp_byte": 0, "gfe": 0,
            "g_usip": set(), "rfip": set(),
            "avg_durat": 0.0, "avg_flow_dst": 0,
            "last_reply_ts": None, "disp_interval": 1.0,
        })

        # F3 fix: track cumulative dropped packets per src_ip from blocked OFP
        # flow entries (priority 80/90/100, empty instructions = drop).
        # Sent to backend via ZMQ telemetry as "dropped_packets" aggregate so
        # the UI shows real physical packet drops, not just ML event count.
        self._blocked_prev_pkts: dict[str, int] = {}  # src_ip → last seen pkt_count

        self._pkt_in_count: dict = collections.defaultdict(int)

        self._port_counts: dict = collections.defaultdict(int)

        # Set of currently banned src IPs — updated by _apply_command.
        # Throttled packets check this before forwarding so banned IPs
        # are dropped even when the flow table is bypassed by OFPPacketOut.
        self._banned_ips: set = set()

        # Cooldown tracker: after stop_all_attacks() clears IPs, suppress
        # is_flood_switch for 2 polling intervals so baseline isn't flagged.
        # Key: dpid → intervals_remaining
        self._cooldown_intervals: dict[int, int] = {}
        self._COOLDOWN_INTERVALS = 3  # suppress flood detection for N intervals after clear

        # Track dominant ip_proto per switch per polling interval.
        # Counts {dpid: {proto_num: count}} — reset each FlowStats reply.
        # Injected into switch_stats as ip_proto for RF classification.
        # ICMP=1, TCP/SYN=6, UDP=17  (matches FILENAME_PROTO_MAP in training)
        self._switch_proto: dict = collections.defaultdict(lambda: collections.defaultdict(int))

        # Per-src-IP protocol tracker: src_ip → last seen ip_proto
        # Reset each FlowStats interval. Used to inject correct ip_proto per flow.
        self._src_proto: dict = collections.defaultdict(lambda: collections.defaultdict(int))

        # PacketIn rate limiter — prevents controller overload during rand-source floods.
        # Key: dpid → (count_in_window, window_start_monotonic)
        # When PacketIn rate > PKT_IN_RATE_LIMIT/s, we forward without installing
        # per-src-IP flow rules. This prevents 19M+ flow entries overwhelming OVS
        # and Ryu's event loop crashing under --rand-source --flood attacks.
        self._pkt_in_rate: dict = {}   # dpid → (count, window_start)
        self._PKT_IN_RATE_LIMIT = 150  # Reduced from 200 — safer for VMware without losing attack visibility

        hub.spawn(self._stats_poll_loop)
        hub.spawn(self._command_listener)

    # ------------------------------------------------------------------
    # OpenFlow handshake
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        self._datapaths[dp.id] = dp
        FatTreeController._connected_count = len(self._datapaths)
        self.logger.info(
            '✔ Switch CONNECTED  dpid=%016x  (%d/%d switches)',
            dp.id, len(self._datapaths), 20
        )
        # Fix B: push switch count via ZMQ so topology.py can poll it
        # without needing the Ryu REST topology app (which gives 404).
        self._push({
            "type":          "switch_count",
            "connected":     len(self._datapaths),
        })

        # Flush ALL existing flow rules (priority 1) so old rules without
        # ip_proto in the match are removed immediately. New rules installed
        # by packet_in_handler will include ip_proto for correct RF classification.
        flush_match = parser.OFPMatch()
        flush_mod   = parser.OFPFlowMod(
            datapath  = dp,
            command   = ofp.OFPFC_DELETE,
            out_port  = ofp.OFPP_ANY,
            out_group = ofp.OFPG_ANY,
            priority  = 1,
            match     = flush_match,
        )
        dp.send_msg(flush_mod)

        # Install table-miss rule (send unknown packets to controller)
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst    = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod     = parser.OFPFlowMod(datapath=dp, priority=0,
                                    match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def switch_disconnect_handler(self, ev):
        dp   = ev.datapath
        dpid = dp.id
        self._datapaths.pop(dpid, None)
        FatTreeController._connected_count = len(self._datapaths)
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
        msg    = ev.msg
        dp     = msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dpid   = dp.id
        in_port = msg.match["in_port"]

        # ── Rate limiter — MUST be FIRST, before any parsing ──────────────────
        now_mono    = time.monotonic()
        _rate_entry = self._pkt_in_rate.get(dpid, (0, now_mono))
        _rate_count, _rate_start = _rate_entry
        if now_mono - _rate_start >= 1.0:
            self._pkt_in_rate[dpid] = (1, now_mono)
            _throttled = False
        else:
            _rate_count += 1
            self._pkt_in_rate[dpid] = (_rate_count, _rate_start)
            _throttled = (_rate_count > self._PKT_IN_RATE_LIMIT)

        if _throttled:
            self._pkt_in_count[dpid] += 1

            try:
                _raw_pkt = packet.Packet(msg.data)
                _raw_ip  = _raw_pkt.get_protocol(ipv4.ipv4)
                if _raw_ip and _raw_ip.src in self._banned_ips:
                    return  # drop silently — IP is banned
            except Exception:
                pass  # parse failed — fall through to forward

            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=None)
            else:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return   # ← exit immediately, zero further processing

        # ── Full processing path (not throttled) ───────────────────────────────
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # ── ARP — must come before IPv4 check ─────────────────────────────────
        if eth.ethertype == 0x0806:  # ARP
            self._mac_to_port[dpid][eth.src] = in_port
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=None)
            else:
                out = parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
            return

        # ── Non-ARP, non-IPv4 (LLDP, IPv6 etc.) ──────────────────────────────
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            self._mac_to_port[dpid][eth.src] = in_port
            if eth.dst not in self._mac_to_port[dpid]:
                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    out = parser.OFPPacketOut(
                        datapath=dp, buffer_id=msg.buffer_id,
                        in_port=in_port, actions=actions, data=None)
                else:
                    out = parser.OFPPacketOut(
                        datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=in_port, actions=actions, data=msg.data)
                dp.send_msg(out)
            return

        # ── IPv4 full processing ───────────────────────────────────────────────
        src_ip = ip4.src
        dst_ip = ip4.dst

        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        udp_pkt  = pkt.get_protocol(udp.udp)

        proto         = "TCP" if tcp_pkt else ("ICMP" if icmp_pkt else ("UDP" if udp_pkt else "OTHER"))
        tcp_flags_syn = bool(tcp_pkt and (tcp_pkt.bits & 0x02))
        tcp_flags_ack = bool(tcp_pkt and (tcp_pkt.bits & 0x10))

        # Count for rate_pkt_in
        self._pkt_in_count[dpid] += 1

        # F5 fix: _src_proto stores the MOST RECENT proto seen for each src_ip
        if ip4.proto:
            self._switch_proto[dpid][ip4.proto] += 1
            self._src_proto[dpid][src_ip] = ip4.proto   # overwrite with latest

        # Push telemetry for SYN tracking and packet_in events
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

        self._mac_to_port[dpid][eth.src] = in_port

        if eth.dst in self._mac_to_port[dpid]:
            out_port = self._mac_to_port[dpid][eth.dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD and ip4.proto:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,
                ip_proto=ip4.proto,
                ipv4_src=src_ip,
                eth_dst=eth.dst,
            )
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=1,
                    idle_timeout=300, hard_timeout=0,
                    buffer_id=msg.buffer_id,
                    match=match, instructions=inst)
                dp.send_msg(mod)
                return
            else:
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=1,
                    idle_timeout=300, hard_timeout=0,
                    match=match, instructions=inst)
                dp.send_msg(mod)

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

        agg      = self._switch_agg[dpid]
        prev_ts  = agg["last_reply_ts"]
        interval = (now - prev_ts) if prev_ts else 1.0
        agg["last_reply_ts"] = now
        agg["disp_interval"] = max(interval, 0.001)

        # Only the switch-wide _switch_proto is reset (it's a per-interval tally).
        # _src_proto (per-src-ip persistent cache) is intentionally NEVER cleared.
        self._switch_proto[dpid].clear()

        # Tick down cooldown counter for this switch each polling interval.
        if self._cooldown_intervals.get(dpid, 0) > 0:
            self._cooldown_intervals[dpid] -= 1

        total_pkt  = 0
        total_byte = 0
        durations  = []
        dst_ips    = set()
        src_ips    = set()

        # Bug 1 fix: compute rate_pkt_in BEFORE the per-flow loop
        _rate_pkt_in_now = self._pkt_in_count.get(dpid, 0) / max(interval, 0.001)
        self._pkt_in_count[dpid] = 0   # reset immediately after reading

        _sw_total_now = sum(s.packet_count for s in body)
        _prev_entry   = self._switch_prev_total.get(dpid)
        if _prev_entry is None:
            self._switch_prev_total[dpid] = _sw_total_now
            agg["switch_delta_pps"] = 0.0
        else:
            _sw_delta = max(_sw_total_now - _prev_entry, 0)
            self._switch_prev_total[dpid] = _sw_total_now
            _flow_based_delta_pps = _sw_delta / max(interval, 0.1)
            agg["switch_delta_pps"] = max(_flow_based_delta_pps, _rate_pkt_in_now)

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

            # F3 fix: detect blocked flow entries (priority 80/90/100 = drop rules)
            if stat.priority in (80, 90, 100):
                _blocked_src = match.get("ipv4_src")
                if _blocked_src:
                    _prev_pkts = self._blocked_prev_pkts.get(_blocked_src, 0)
                    _delta     = max(stat.packet_count - _prev_pkts, 0)
                    self._blocked_prev_pkts[_blocked_src] = stat.packet_count
                    if _delta > 0:
                        self._push({
                            "type":     "dropped_delta",
                            "src_ip":   _blocked_src,
                            "delta":    _delta,
                        })

            _total_s = stat.duration_sec + stat.duration_nsec / 1e9
            _total_s = max(_total_s, 1e-9)
            pps  = stat.packet_count / _total_s
            bps  = stat.byte_count   / _total_s
            ppns = pps / 1e9
            bpns = bps / 1e9

            src_ip = match.get("ipv4_src")
            if not src_ip or src_ip == "0.0.0.0":
                continue

            switch_delta_pps = agg.get("switch_delta_pps", 0.0)

            # Cooldown: if we just cleared an attack, suppress flood detection
            # for _COOLDOWN_INTERVALS intervals so baseline isn't misclassified.
            _cooldown_left = self._cooldown_intervals.get(dpid, 0)
            if _cooldown_left > 0:
                is_flood_switch = False  # grace period — treat as normal
            else:
                is_flood_switch = switch_delta_pps >= 1.0

            if is_flood_switch:
                if stat.packet_count < 1:
                    continue
            else:
                if stat.packet_count < 1 or pps < 0.05:  # lowered from 0.5 — catches ICMP/UDP early
                    continue

            _flow_ip_proto = int(match.get("ip_proto", 0))
            if not _flow_ip_proto:
                _flow_ip_proto = int(self._src_proto[dpid].get(src_ip, 0))
            if not _flow_ip_proto:
                proto_counts = self._switch_proto.get(dpid, {})
                if proto_counts:
                    _flow_ip_proto = max(proto_counts, key=proto_counts.get)

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
                    "ip_proto":                 _flow_ip_proto,
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
        agg["rate_pkt_in"]  = _rate_pkt_in_now

    # ------------------------------------------------------------------
    # PortStats reply
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        dpid   = ev.msg.datapath.id
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
                hub.sleep(0.04)  # 40ms stagger — prevents blasting all 20 switches at once (VMware fix)

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
    # Command listener
    # ------------------------------------------------------------------

    def _command_listener(self):
        self._cmd_sock.setsockopt(zmq.RCVTIMEO, 0)
        while True:
            try:
                raw = self._cmd_sock.recv(zmq.NOBLOCK)
                cmd = json.loads(raw)
                self._apply_command(cmd)
            except zmq.Again:
                hub.sleep(0.05)
            except Exception as e:
                self.logger.warning("Command error: %s", e)
                hub.sleep(0.05)

    def _apply_command(self, cmd: dict):
        """Apply an OpenFlow mitigation rule to all connected switches.

        L17 / Feature 1 fix: the 'block' action now reads an optional 'ttl'
        field from the command dict (seconds).
          ttl=None or absent → hard_timeout=0  (permanent, for manual blocks)
          ttl=3600           → hard_timeout=3600 (auto-block, self-expires at switch)

        This mirrors the backend state machine's TTL so the OFP rule
        self-cleans at the switch level even if the backend is offline.
        """
        action = cmd.get("action")
        src_ip = cmd.get("src_ip")
        ttl    = cmd.get("ttl")   # int seconds or None

        # Maintain _banned_ips so the throttled fast-path can also drop banned packets.
        if action in ("block", "rate_limit", "quarantine"):
            self._banned_ips.add(src_ip)
        elif action == "clear":
            self._banned_ips.discard(src_ip)
            # F3 fix: reset drop counter so a re-offending IP starts fresh
            self._blocked_prev_pkts.pop(src_ip, None)
            # BUG FIX: also purge stale cached protocol for this IP across all switches.
            # Without this, the old attack protocol (ICMP/TCP/UDP) stays in _src_proto
            # and gets re-injected into RF features after the IP resumes normal traffic,
            # causing misclassification on the next legitimate flow from that IP.
            for dpid_key in list(self._src_proto.keys()):
                self._src_proto[dpid_key].pop(src_ip, None)
            # BUG FIX: reset switch_prev_total so stale attack packet_count deltas
            # don't carry over into the next polling interval after stop_all_attacks().
            # Without this, the switch_delta_pps stays abnormally high for 1-2 intervals
            # after the attack stops, causing baseline pings to be flagged as flood traffic.
            for dpid_key in list(self._switch_prev_total.keys()):
                self._switch_prev_total.pop(dpid_key, None)
            # Also reset pkt_in_count per switch so rate_pkt_in drops to zero cleanly.
            for dpid_key in list(self._pkt_in_count.keys()):
                self._pkt_in_count[dpid_key] = 0
            # Cooldown: suppress is_flood_switch for N intervals on all switches
            # so baseline traffic right after stop_all_attacks() isn't misclassified.
            for dpid_key in list(self._datapaths.keys()):
                self._cooldown_intervals[dpid_key] = self._COOLDOWN_INTERVALS

        for dpid, dp in list(self._datapaths.items()):
            parser = dp.ofproto_parser
            ofp    = dp.ofproto

            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

            # SLIP-THROUGH FIX: before installing any drop rule, delete ALL existing
            # forwarding flow entries for this src_ip across ALL switches.
            # Without this, priority=1 forwarding rules installed by packet_in_handler
            # (which have more specific matches: in_port + ip_proto + eth_dst) can
            # still match and FORWARD attacker packets even after a priority=80/90/100
            # drop rule is installed — OVS picks the most specific match, not just
            # the highest priority, when match fields differ.
            if action in ("block", "quarantine", "rate_limit"):
                flush_mod = parser.OFPFlowMod(
                    datapath  = dp,
                    command   = ofp.OFPFC_DELETE,
                    out_port  = ofp.OFPP_ANY,
                    out_group = ofp.OFPG_ANY,
                    priority  = 1,
                    match     = match)
                dp.send_msg(flush_mod)

            if action == "block":
                # ttl=None → permanent manual block (hard_timeout=0)
                # ttl=N    → auto-block, OVS self-removes after N seconds
                hard_timeout = int(ttl) if ttl is not None else 0
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=100,
                    idle_timeout=0, hard_timeout=hard_timeout,
                    match=match, instructions=[])
                dp.send_msg(mod)

            elif action == "quarantine":
                # hard_timeout matches PHASE1_DURATION_HIGH (5s) + 3s buffer = 8s
                # so OVS rule self-cleans if backend misses the clear command.
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=90,
                    idle_timeout=8, hard_timeout=8,
                    match=match, instructions=[])
                dp.send_msg(mod)

            elif action == "rate_limit":
                # hard_timeout = quarantine timeout + Phase1 observation = 10s
                mod = parser.OFPFlowMod(
                    datapath=dp, priority=80,
                    idle_timeout=10, hard_timeout=10,
                    match=match, instructions=[])
                dp.send_msg(mod)

            elif action == "clear":
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
        agg = self._switch_agg[dpid]
        n   = max(agg["gfe"], 1)

        # Dominant ip_proto this interval: pick the protocol with most PacketIn events.
        # Falls back to 0 if no IPv4 packets seen yet.
        proto_counts = self._switch_proto.get(dpid, {})
        if proto_counts:
            dominant_proto = max(proto_counts, key=proto_counts.get)
        else:
            dominant_proto = 0

        return {
            "disp_pakt":     agg["disp_pakt"],
            "disp_byte":     agg["disp_byte"],
            "mean_pkt":      agg["disp_pakt"] / n,
            "mean_byte":     agg["disp_byte"] / n,
            "avg_durat":     agg["avg_durat"],
            "avg_flow_dst":  agg["avg_flow_dst"],
            "rate_pkt_in":   agg.get("rate_pkt_in", 0),
            "disp_interval": agg["disp_interval"],
            "gfe":           agg["gfe"],
            "g_usip":        len(agg["g_usip"]),
            "rfip":          self._count_rfip(dpid),
            "gsp":           self._port_counts.get(dpid, 0),
            "ip_proto":      dominant_proto,
        }

    def _count_rfip(self, dpid: int) -> int:
        import ipaddress
        agg    = self._switch_agg[dpid]
        sample = next(iter(agg["g_usip"]), None)
        if not sample:
            return 0
        try:
            ipaddress.ip_network(f"{sample}/24", strict=False)
        except ValueError:
            return 0
        return max(0, agg["avg_flow_dst"] - 1)

    def _push(self, msg: dict) -> None:
        try:
            self._tel_sock.send_json(msg, zmq.NOBLOCK)
        except zmq.Again:
            pass