from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


MODBUS_PUBLIC_FUNCTION_CODES = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x0B, 0x0C, 0x0F, 0x10,
    0x11, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x2B,
}

MODBUS_FUNCTION_NAMES = {
    0x01: "read_coils",
    0x02: "read_discrete_inputs",
    0x03: "read_holding_registers",
    0x04: "read_input_registers",
    0x05: "write_single_coil",
    0x06: "write_single_register",
    0x07: "read_exception_status",
    0x08: "diagnostics",
    0x0B: "get_comm_event_counter",
    0x0C: "get_comm_event_log",
    0x0F: "write_multiple_coils",
    0x10: "write_multiple_registers",
    0x11: "report_server_id",
    0x14: "read_file_record",
    0x15: "write_file_record",
    0x16: "mask_write_register",
    0x17: "read_write_multiple_registers",
    0x18: "read_fifo_queue",
    0x2B: "encapsulated_interface_transport",
}


@dataclass
class FrameResult:
    frames: List[bytes]
    discarded_bytes: int = 0
    need_more_data: bool = False


class StreamBuffer:
    def __init__(self, framer: Callable[[bytearray], FrameResult], max_bytes=4*1024*1024):
        self.framer = framer
        self.max_bytes = int(max_bytes)
        self.buffer = bytearray()
        self.discarded_bytes = 0
        self.frames_emitted = 0
        self.limit_resets = 0

    def feed(self, data: bytes) -> List[bytes]:
        if data:
            self.buffer.extend(data)
        if len(self.buffer) > self.max_bytes:
            self.discarded_bytes += len(self.buffer)
            self.buffer.clear()
            self.limit_resets += 1
            return []
        result = self.framer(self.buffer)
        self.discarded_bytes += result.discarded_bytes
        self.frames_emitted += len(result.frames)
        return result.frames

    def stats(self):
        return {
            "buffered_bytes": len(self.buffer),
            "discarded_bytes": self.discarded_bytes,
            "frames_emitted": self.frames_emitted,
            "limit_resets": self.limit_resets,
        }


def modbus_tcp_framer(buffer: bytearray) -> FrameResult:
    frames = []
    discarded = 0

    while len(buffer) >= 8:
        protocol_id = int.from_bytes(buffer[2:4], "big")
        length = int.from_bytes(buffer[4:6], "big")
        total = 6 + length

        if (
            protocol_id != 0
            or length < 2
            or length > 254
            or total < 8
            or total > 260
        ):
            del buffer[0]
            discarded += 1
            continue

        if len(buffer) < total:
            return FrameResult(frames, discarded, True)

        raw_function_code = buffer[7]
        base_function_code = raw_function_code & 0x7F

        if base_function_code not in MODBUS_PUBLIC_FUNCTION_CODES:
            del buffer[0]
            discarded += 1
            continue

        # Exception responses contain FC|0x80 plus one exception byte.
        if raw_function_code & 0x80 and length != 3:
            del buffer[0]
            discarded += 1
            continue

        frames.append(bytes(buffer[:total]))
        del buffer[:total]

    return FrameResult(frames, discarded, bool(buffer))


def _mqtt_remaining(data: bytearray, offset=1) -> Tuple[Optional[int], int]:
    value, multiplier, consumed = 0, 1, 0
    while consumed < 4 and offset + consumed < len(data):
        encoded = data[offset + consumed]
        value += (encoded & 0x7F) * multiplier
        consumed += 1
        if not encoded & 0x80:
            return value, consumed
        multiplier *= 128
    return None, 0


def mqtt_framer(buffer: bytearray) -> FrameResult:
    frames, discarded = [], 0
    while len(buffer) >= 2:
        packet_type = buffer[0] >> 4
        if packet_type == 0:
            del buffer[0]
            discarded += 1
            continue
        remaining, consumed = _mqtt_remaining(buffer)
        if remaining is None:
            return FrameResult(frames, discarded, True)
        total = 1 + consumed + remaining
        if total > 16 * 1024 * 1024:
            del buffer[0]
            discarded += 1
            continue
        if len(buffer) < total:
            return FrameResult(frames, discarded, True)
        frames.append(bytes(buffer[:total]))
        del buffer[:total]
    return FrameResult(frames, discarded, bool(buffer))


def tls_record_framer(buffer: bytearray) -> FrameResult:
    frames, discarded = [], 0
    valid_types = {20, 21, 22, 23, 24}
    while len(buffer) >= 5:
        content_type = buffer[0]
        version_major = buffer[1]
        length = int.from_bytes(buffer[3:5], "big")
        if content_type not in valid_types or version_major != 3 or length > 18432:
            del buffer[0]
            discarded += 1
            continue
        total = 5 + length
        if len(buffer) < total:
            return FrameResult(frames, discarded, True)
        frames.append(bytes(buffer[:total]))
        del buffer[:total]
    return FrameResult(frames, discarded, bool(buffer))


def tpkt_framer(buffer: bytearray) -> FrameResult:
    frames, discarded = [], 0
    while len(buffer) >= 4:
        if buffer[0:2] != b"\x03\x00":
            del buffer[0]
            discarded += 1
            continue
        total = int.from_bytes(buffer[2:4], "big")
        if total < 7 or total > 65535:
            del buffer[0]
            discarded += 1
            continue
        if len(buffer) < total:
            return FrameResult(frames, discarded, True)
        frames.append(bytes(buffer[:total]))
        del buffer[:total]
    return FrameResult(frames, discarded, bool(buffer))


def dnp3_framer(buffer: bytearray) -> FrameResult:
    frames, discarded = [], 0
    while True:
        if len(buffer) < 10:
            return FrameResult(frames, discarded, bool(buffer))
        start = buffer.find(b"\x05\x64")
        if start < 0:
            keep = 1 if buffer[-1:] == b"\x05" else 0
            remove = len(buffer) - keep
            del buffer[:remove]
            discarded += remove
            return FrameResult(frames, discarded, bool(buffer))
        if start:
            del buffer[:start]
            discarded += start
        if len(buffer) < 10:
            return FrameResult(frames, discarded, True)
        length = buffer[2]
        if length < 5:
            del buffer[0]
            discarded += 1
            continue
        user_length = length - 5
        total = 10 + user_length + 2 * math.ceil(user_length / 16)
        if len(buffer) < total:
            return FrameResult(frames, discarded, True)
        frames.append(bytes(buffer[:total]))
        del buffer[:total]
