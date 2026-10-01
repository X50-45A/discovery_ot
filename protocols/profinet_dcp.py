from collections import defaultdict
from datetime import datetime
import ipaddress

from scapy.all import Dot1Q, Ether

from core.base import ProtocolPlugin
from core.model_resolver import ModelResolver


PROFINET_ETHERTYPE = 0x8892
DCP_FRAME_ID_MIN = 0xFEFD
DCP_FRAME_ID_MAX = 0xFEFF
DCP_SERVICE_IDENTIFY = 0x05
DEVICE_ROLE_BITS = {
    0x01: "io_device",
    0x02: "io_controller",
    0x04: "io_multidevice",
    0x08: "pn_supervisor",
}


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def decode_text(value):
    return value.decode("utf-8", errors="replace").strip(" \t\r\n\x00") or None


def ipv4_text(value):
    return str(ipaddress.IPv4Address(value)) if len(value) == 4 else None


class ProfinetDcpPlugin(ProtocolPlugin):
    plugin_id = "profinet_dcp"
    display_name = "PROFINET DCP"
    description = (
        "Descubrimiento pasivo PROFINET DCP con nombre de estacion, IP, "
        "Vendor ID, Device ID, rol y resolucion de identidad."
    )
    version = "1.1"
    bpf_filter = "ether proto 0x8892"

    def __init__(self, config=None):
        super().__init__(config)
        self.devices = defaultdict(self._new_device)
        self.statistics = {
            "profinet_frames": 0,
            "dcp_frames": 0,
            "identify_requests": 0,
            "identify_responses": 0,
            "malformed_frames": 0,
        }
        self.resolver = ModelResolver(
            modbus_catalog_path=self.config.get("model_catalog"),
            profinet_vendor_catalog_path=self.config.get(
                "profinet_vendor_catalog"
            ),
            profinet_model_catalog_path=self.config.get(
                "profinet_model_catalog"
            ),
        )

    @staticmethod
    def _new_device():
        return {
            "source_mac": None,
            "destination_macs": set(),
            "station_name": None,
            "alias_name": None,
            "device_type": None,
            "vendor_id": None,
            "device_id": None,
            "device_roles": set(),
            "ip_addresses": set(),
            "subnet_masks": set(),
            "gateways": set(),
            "frames": 0,
            "identify_responses": 0,
            "first_seen": None,
            "last_seen": None,
            "unknown_blocks": [],
            "identification": None,
        }

    def process_packet(self, packet, context):
        if not packet.haslayer(Ether):
            return
        ether = packet[Ether]
        if ether.type == PROFINET_ETHERTYPE:
            payload = bytes(ether.payload)
        elif ether.type == 0x8100 and packet.haslayer(Dot1Q):
            vlan = packet[Dot1Q]
            if vlan.type != PROFINET_ETHERTYPE:
                return
            payload = bytes(vlan.payload)
        else:
            return

        self.statistics["profinet_frames"] += 1
        parsed = self._parse_header(payload)
        if parsed is None:
            return
        self.statistics["dcp_frames"] += 1
        if parsed["service_id"] != DCP_SERVICE_IDENTIFY:
            return
        if parsed["service_type"] == 0x00:
            self.statistics["identify_requests"] += 1
            return

        self.statistics["identify_responses"] += 1
        device = self.devices[ether.src.lower()]
        device["source_mac"] = ether.src.lower()
        device["destination_macs"].add(ether.dst.lower())
        device["frames"] += 1
        device["identify_responses"] += 1
        timestamp = now_iso()
        device["first_seen"] = device["first_seen"] or timestamp
        device["last_seen"] = timestamp

        for block in self._iter_blocks(parsed["data"]):
            self._apply_block(device, block)

        device["identification"] = self.resolver.resolve_profinet(
            vendor_id=device["vendor_id"],
            device_id=device["device_id"],
            device_type=device["device_type"],
            station_name=device["station_name"],
            alias_name=device["alias_name"],
        )

    @staticmethod
    def _parse_header(payload):
        if len(payload) < 12:
            return None
        frame_id = int.from_bytes(payload[0:2], "big")
        if not DCP_FRAME_ID_MIN <= frame_id <= DCP_FRAME_ID_MAX:
            return None
        data_length = int.from_bytes(payload[10:12], "big")
        if 12 + data_length > len(payload):
            return None
        return {
            "frame_id": frame_id,
            "service_id": payload[2],
            "service_type": payload[3],
            "xid": int.from_bytes(payload[4:8], "big"),
            "data": payload[12:12 + data_length],
        }

    @staticmethod
    def _iter_blocks(data):
        offset = 0
        while offset + 4 <= len(data):
            option = data[offset]
            suboption = data[offset + 1]
            length = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
            if offset + length > len(data):
                break
            raw = data[offset:offset + length]
            offset += length
            if length % 2 and offset < len(data):
                offset += 1
            value = raw[2:] if len(raw) >= 2 else b""
            yield {"option": option, "suboption": suboption, "value": value}

    @staticmethod
    def _apply_block(device, block):
        option, suboption, value = (
            block["option"], block["suboption"], block["value"]
        )
        if option == 0x01 and suboption == 0x02 and len(value) >= 12:
            device["ip_addresses"].add(ipv4_text(value[0:4]))
            device["subnet_masks"].add(ipv4_text(value[4:8]))
            device["gateways"].add(ipv4_text(value[8:12]))
        elif option == 0x02 and suboption == 0x01:
            device["device_type"] = decode_text(value)
        elif option == 0x02 and suboption == 0x02:
            device["station_name"] = decode_text(value)
        elif option == 0x02 and suboption == 0x03 and len(value) >= 4:
            device["vendor_id"] = int.from_bytes(value[0:2], "big")
            device["device_id"] = int.from_bytes(value[2:4], "big")
        elif option == 0x02 and suboption == 0x04 and value:
            role_value = int.from_bytes(value[:2], "big") if len(value) >= 2 else value[0]
            for bit, name in DEVICE_ROLE_BITS.items():
                if role_value & bit:
                    device["device_roles"].add(name)
        elif option == 0x02 and suboption == 0x06:
            device["alias_name"] = decode_text(value)
        elif len(device["unknown_blocks"]) < 20:
            device["unknown_blocks"].append({
                "option": option,
                "suboption": suboption,
                "value_hex": value.hex(),
            })

    @staticmethod
    def _serialize(device):
        return {
            "source_mac": device["source_mac"],
            "destination_macs": sorted(device["destination_macs"]),
            "station_name": device["station_name"],
            "alias_name": device["alias_name"],
            "device_type": device["device_type"],
            "vendor_id": (
                f"0x{device['vendor_id']:04X}"
                if device["vendor_id"] is not None else None
            ),
            "device_id": (
                f"0x{device['device_id']:04X}"
                if device["device_id"] is not None else None
            ),
            "device_roles": sorted(device["device_roles"]),
            "ip_addresses": sorted(x for x in device["ip_addresses"] if x),
            "subnet_masks": sorted(x for x in device["subnet_masks"] if x),
            "gateways": sorted(x for x in device["gateways"] if x),
            "frames": device["frames"],
            "identify_responses": device["identify_responses"],
            "first_seen": device["first_seen"],
            "last_seen": device["last_seen"],
            "identification": device["identification"],
            "unknown_blocks": device["unknown_blocks"],
        }

    def finalize(self, context):
        devices = {
            mac: self._serialize(device)
            for mac, device in sorted(self.devices.items())
        }
        context.protocol_results[self.plugin_id] = {
            "passive_only": True,
            "device_count": len(devices),
            "statistics": dict(self.statistics),
            "devices": devices,
        }
