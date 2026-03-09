import zmq
import json
import time
import threading
import logging
from backend.config import ZMQ_COMMAND_ADDR

log = logging.getLogger(__name__)

_RECONNECT_DELAY_S = 3.0
_SEND_TIMEOUT_MS   = 500


class ZmqCommander:
    """Sends OpenFlow commands to Ryu over ZeroMQ PUSH socket.

    Ryu being offline does not crash the backend — commands are dropped
    with a warning and retried on next reconnect.
    """

    def __init__(self):
        self._lock  = threading.Lock()
        self._ctx   = zmq.Context.instance()
        self._sock  = None
        self._connect()

    def _connect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = self._ctx.socket(zmq.PUSH)
        self._sock.setsockopt(zmq.SNDTIMEO, _SEND_TIMEOUT_MS)
        self._sock.setsockopt(zmq.LINGER, 0)
        self._sock.connect(ZMQ_COMMAND_ADDR)
        log.info("ZMQ commander connected to %s", ZMQ_COMMAND_ADDR)

    def send(self, command: dict) -> None:
        """Send a command dict to Ryu. Non-blocking — drops if Ryu is offline."""
        payload = json.dumps(command).encode()
        with self._lock:
            try:
                self._sock.send(payload, zmq.NOBLOCK)
            except zmq.Again:
                log.debug("ZMQ command dropped (Ryu unavailable): %s", command)
            except zmq.ZMQError as e:
                log.warning("ZMQ send error: %s — reconnecting", e)
                self._reconnect_safe()

    def _reconnect_safe(self) -> None:
        # Called while _lock is held
        try:
            time.sleep(_RECONNECT_DELAY_S)
            self._connect()
        except Exception as exc:
            log.warning("ZMQ commander reconnect failed: %s", exc)

    def close(self) -> None:
        with self._lock:
            if self._sock:
                self._sock.close()


# Module-level singleton — injected into state_machine in main.py
commander = ZmqCommander()