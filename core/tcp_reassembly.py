from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from typing import Dict, Hashable, Iterable, Optional, Tuple

from scapy.all import IP, IPv6, TCP


FlowKey = Tuple[int, str, int, str, int]


@dataclass
class ReassemblyEvent:
    flow_key: FlowKey
    data: bytes = b""
    opened: bool = False
    closed: bool = False
    reset: bool = False
    gap_detected: bool = False
    truncated: bool = False


@dataclass
class _FlowState:
    next_seq: Optional[int] = None
    pending: Dict[int, bytes] = field(default_factory=dict)
    last_seen: float = field(default_factory=monotonic)
    syn_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    delivered_bytes: int = 0
    retransmitted_bytes: int = 0
    overlap_bytes: int = 0
    out_of_order_segments: int = 0


class TcpReassembler:
    """Directional TCP byte-stream reassembly for packet/PCAP analysis.

    This class never creates network traffic.  It accepts Scapy packets and
    emits only newly contiguous bytes.  Each direction of a TCP connection is
    represented by a different FlowKey.

    Policy for captures that begin mid-session:
    * The first segment carrying payload establishes the initial sequence.
    * If a later lower sequence arrives before any bytes were emitted, the
      initial sequence is moved backwards.
    * Once data has been emitted, bytes older than next_seq are treated as
      retransmission/overlap and are not emitted twice.
    """

    def __init__(
        self,
        *,
        flow_timeout: float = 120.0,
        max_active_flows: int = 10_000,
        max_pending_segments: int = 1_024,
        max_pending_bytes: int = 4 * 1024 * 1024,
    ):
        self.flow_timeout = float(flow_timeout)
        self.max_active_flows = int(max_active_flows)
        self.max_pending_segments = int(max_pending_segments)
        self.max_pending_bytes = int(max_pending_bytes)
        self.flows: Dict[FlowKey, _FlowState] = {}
        self.statistics = {
            "packets_seen": 0,
            "payload_segments": 0,
            "bytes_received": 0,
            "bytes_emitted": 0,
            "retransmitted_bytes": 0,
            "overlap_bytes": 0,
            "out_of_order_segments": 0,
            "flows_created": 0,
            "flows_expired": 0,
            "flows_evicted": 0,
            "flows_reset": 0,
            "flows_closed": 0,
            "limit_drops": 0,
        }

    @staticmethod
    def flow_key(packet) -> Optional[FlowKey]:
        if not packet.haslayer(TCP):
            return None
        tcp = packet[TCP]
        if packet.haslayer(IP):
            ip = packet[IP]
            return (4, ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
        if packet.haslayer(IPv6):
            ip = packet[IPv6]
            return (6, ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
        return None

    @staticmethod
    def reverse_key(key: FlowKey) -> FlowKey:
        version, src, sport, dst, dport = key
        return (version, dst, dport, src, sport)

    def feed(self, packet, now: Optional[float] = None) -> Optional[ReassemblyEvent]:
        key = self.flow_key(packet)
        if key is None:
            return None
        self.statistics["packets_seen"] += 1
        current = monotonic() if now is None else float(now)
        self.expire(current)
        tcp = packet[TCP]
        flags = int(tcp.flags)
        syn = bool(flags & 0x02)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
        payload = bytes(tcp.payload)
        sequence = int(tcp.seq) + (1 if syn else 0)

        state = self.flows.get(key)
        opened = False
        if state is None:
            self._ensure_capacity(current)
            state = _FlowState()
            self.flows[key] = state
            self.statistics["flows_created"] += 1
            opened = True
        state.last_seen = current
        state.syn_seen |= syn

        event = ReassemblyEvent(flow_key=key, opened=opened)
        if payload:
            self.statistics["payload_segments"] += 1
            self.statistics["bytes_received"] += len(payload)
            accepted = self._insert(state, sequence, payload)
            if not accepted:
                event.truncated = True
            contiguous = self._drain(state)
            if contiguous:
                event.data = contiguous
                self.statistics["bytes_emitted"] += len(contiguous)

        if rst:
            state.rst_seen = True
            event.reset = True
            event.closed = True
            self.statistics["flows_reset"] += 1
            self.flows.pop(key, None)
        elif fin:
            state.fin_seen = True
            event.closed = True
            self.statistics["flows_closed"] += 1
            self.flows.pop(key, None)
        return event

    def _insert(self, state: _FlowState, seq: int, data: bytes) -> bool:
        if state.next_seq is None:
            state.next_seq = seq
        if state.delivered_bytes == 0 and seq < state.next_seq:
            state.next_seq = seq

        end = seq + len(data)
        if end <= state.next_seq:
            state.retransmitted_bytes += len(data)
            self.statistics["retransmitted_bytes"] += len(data)
            return True
        if seq < state.next_seq:
            trim = state.next_seq - seq
            state.overlap_bytes += trim
            self.statistics["overlap_bytes"] += trim
            data = data[trim:]
            seq = state.next_seq
        if not data:
            return True

        # Merge the new segment with pending segments.  For conflicting
        # overlaps, bytes already observed win, producing deterministic output.
        segments = list(state.pending.items()) + [(seq, data)]
        segments.sort(key=lambda item: item[0])
        merged: Dict[int, bytes] = {}
        for start, chunk in segments:
            if not merged:
                merged[start] = chunk
                continue
            prev_start = next(reversed(merged))
            prev = merged[prev_start]
            prev_end = prev_start + len(prev)
            if start > prev_end:
                merged[start] = chunk
                continue
            overlap = prev_end - start
            if overlap >= len(chunk):
                if (start, chunk) == (seq, data):
                    state.retransmitted_bytes += len(chunk)
                    self.statistics["retransmitted_bytes"] += len(chunk)
                continue
            if overlap > 0:
                state.overlap_bytes += overlap
                self.statistics["overlap_bytes"] += overlap
            merged[prev_start] = prev + chunk[max(0, overlap):]
        state.pending = merged

        if seq > state.next_seq:
            state.out_of_order_segments += 1
            self.statistics["out_of_order_segments"] += 1

        pending_bytes = sum(len(chunk) for chunk in state.pending.values())
        if (
            len(state.pending) > self.max_pending_segments
            or pending_bytes > self.max_pending_bytes
        ):
            state.pending.clear()
            state.next_seq = None
            self.statistics["limit_drops"] += 1
            return False
        return True

    @staticmethod
    def _drain(state: _FlowState) -> bytes:
        if state.next_seq is None:
            return b""
        output = bytearray()
        while state.pending:
            start = min(state.pending)
            chunk = state.pending[start]
            if start > state.next_seq:
                break
            state.pending.pop(start)
            if start < state.next_seq:
                trim = state.next_seq - start
                if trim >= len(chunk):
                    continue
                chunk = chunk[trim:]
            output.extend(chunk)
            state.next_seq += len(chunk)
            state.delivered_bytes += len(chunk)
        return bytes(output)

    def expire(self, now: Optional[float] = None) -> Iterable[FlowKey]:
        current = monotonic() if now is None else float(now)
        expired = [
            key for key, state in self.flows.items()
            if current - state.last_seen > self.flow_timeout
        ]
        for key in expired:
            self.flows.pop(key, None)
            self.statistics["flows_expired"] += 1
        return expired

    def _ensure_capacity(self, now: float) -> None:
        self.expire(now)
        if len(self.flows) < self.max_active_flows:
            return
        oldest = min(self.flows, key=lambda key: self.flows[key].last_seen)
        self.flows.pop(oldest, None)
        self.statistics["flows_evicted"] += 1

    def close_all(self) -> None:
        self.flows.clear()

    def stats(self) -> dict:
        return {**self.statistics, "active_flows": len(self.flows)}
