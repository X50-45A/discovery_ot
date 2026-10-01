from __future__ import annotations

from collections import defaultdict

from core.tcp_reassembly import TcpReassembler
from core.stream_framers import StreamBuffer


class TcpStreamMixin:
    """Reusable TCP reassembly integration for protocol plugins."""

    stream_framer = None
    stream_max_bytes = 4 * 1024 * 1024

    def init_tcp_streams(self):
        if self.stream_framer is None:
            raise ValueError("stream_framer must be configured")
        self.tcp_reassembler = TcpReassembler()
        self.stream_buffers = {}
        self.stream_statistics = {
            "stream_frames": 0,
            "stream_errors": 0,
            "stream_closes": 0,
        }

    def feed_tcp_stream(self, packet):
        event = self.tcp_reassembler.feed(packet)
        if event is None:
            return None, []
        if event.truncated:
            self.stream_statistics["stream_errors"] += 1
        stream = self.stream_buffers.get(event.flow_key)
        if stream is None:
            stream = StreamBuffer(self.stream_framer, self.stream_max_bytes)
            self.stream_buffers[event.flow_key] = stream
        frames = stream.feed(event.data)
        self.stream_statistics["stream_frames"] += len(frames)
        if event.closed:
            self.stream_statistics["stream_closes"] += 1
            # Preserve no stale partial bytes after FIN/RST.
            self.stream_buffers.pop(event.flow_key, None)
        return event.flow_key, frames

    def tcp_stream_stats(self):
        buffer_stats = {
            "active_stream_buffers": len(self.stream_buffers),
            "buffered_bytes": sum(len(x.buffer) for x in self.stream_buffers.values()),
            "framer_discarded_bytes": sum(x.discarded_bytes for x in self.stream_buffers.values()),
            "framer_limit_resets": sum(x.limit_resets for x in self.stream_buffers.values()),
        }
        return {
            **self.stream_statistics,
            **self.tcp_reassembler.stats(),
            **buffer_stats,
        }
