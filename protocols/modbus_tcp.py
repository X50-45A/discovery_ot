from collections import defaultdict
import ipaddress

from scapy.all import Ether, IP, TCP

from core.base import ProtocolPlugin
from core.context import now_iso
from core.model_resolver import ModelResolver
from core.stream_framers import (
    MODBUS_FUNCTION_NAMES,
    MODBUS_PUBLIC_FUNCTION_CODES,
    modbus_tcp_framer,
)
from core.stream_plugin import TcpStreamMixin


MODBUS_PORT = 502
MODBUS_EXCEPTION_CODES = {
    0x01: "illegal_function",
    0x02: "illegal_data_address",
    0x03: "illegal_data_value",
    0x04: "server_device_failure",
    0x05: "acknowledge",
    0x06: "server_device_busy",
    0x08: "memory_parity_error",
    0x0A: "gateway_path_unavailable",
    0x0B: "gateway_target_device_failed_to_respond",
}


class ModbusTcpPlugin(TcpStreamMixin, ProtocolPlugin):
    plugin_id = "modbus_tcp"
    display_name = "Modbus/TCP"
    description = (
        "Descubrimiento pasivo Modbus/TCP con reensamblado TCP, "
        "validacion estricta de ADU y extraccion FC 43/14 y FC 17."
    )
    version = "2.5"
    bpf_filter = "tcp port 502"
    stream_framer = staticmethod(modbus_tcp_framer)

    def __init__(self, config=None):
        super().__init__(config)
        self.init_tcp_streams()
        self.assets = defaultdict(self._new_asset)
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
    def _new_asset():
        return {
            "ip": None,
            "macs": set(),
            "clients": set(),
            "unit_ids": set(),
            "function_codes": defaultdict(int),
            "exception_function_codes": defaultdict(int),
            "exception_codes": defaultdict(int),
            "invalid_function_codes": defaultdict(int),
            "requests": 0,
            "responses": 0,
            "decoded_adus": 0,
            "invalid_adus": 0,
            "first_seen": None,
            "last_seen": None,
            "device_id_objects": {},
            "server_id": None, 
            "write_function_count": 0,
            "write_clients": set(),
        }

    def process_packet(self, packet, context):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]

        if tcp.dport == MODBUS_PORT:
            server_ip = ip.dst
            client_ip = ip.src
            direction = "request"
            server_mac = (
                packet[Ether].dst
                if packet.haslayer(Ether)
                else None
            )
        elif tcp.sport == MODBUS_PORT:
            server_ip = ip.src
            client_ip = ip.dst
            direction = "response"
            server_mac = (
                packet[Ether].src
                if packet.haslayer(Ether)
                else None
            )
        else:
            return

        if context.network is not None:
            try:
                if ipaddress.ip_address(server_ip) not in context.network:
                    return
            except ValueError:
                return

        asset = self.assets[server_ip]
        asset["ip"] = server_ip
        asset["clients"].add(client_ip)
        if server_mac:
            asset["macs"].add(server_mac.lower())

        timestamp = now_iso()
        asset["first_seen"] = asset["first_seen"] or timestamp
        asset["last_seen"] = timestamp
        asset["requests" if direction == "request" else "responses"] += 1

        _, frames = self.feed_tcp_stream(packet)
        for adu in frames:
            self._process_adu(
                asset=asset,
                adu=adu,
                direction=direction,
                client_ip=client_ip,
            )

    @staticmethod
    def _risk_level(score):
        if score >= 80:
            return "HIGH"

        if score >= 50:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _risk_score(asset):
        score = 30

        write_detected = any(
            fc in asset["function_codes"]
            for fc in (5, 6, 15, 16)
        )

        if write_detected:
            score += 40

        if len(asset["write_clients"]) > 1:
            score += 15

        if asset["exception_codes"]:
            score += 5

        if asset["invalid_function_codes"]:
            score += 10

        return min(score, 100)


    @staticmethod
    def _security_findings(asset):
            findings = []

            findings.append(
                {
                    "severity": "HIGH",
                    "title": "Modbus/TCP without authentication",
                    "description": (
                        "Modbus/TCP provides no native "
                        "authentication mechanism."
                    ),
                }
            )

            findings.append(
                {
                    "severity": "HIGH",
                    "title": "Modbus/TCP without encryption",
                    "description": (
                        "Traffic is transmitted in plaintext "
                        "and may be exposed to interception."
                    ),
                }
            )

            write_detected = any(
                fc in asset["function_codes"]
                for fc in (5, 6, 15, 16)
            )

            if write_detected:
                findings.append(
                    {
                        "severity": "HIGH",
                        "title": "Write operations observed",
                        "description": (
                            "Write functions FC05, FC06, "
                            "FC15 or FC16 were observed."
                        ),
                    }
                )

                findings.append(
                    {
                        "severity": "MEDIUM",
                        "title": "Susceptible to replay attacks",
                        "description": (
                            "Observed write operations could "
                            "potentially be replayed by an attacker."
                        ),
                    }
                )

            if len(asset["write_clients"]) > 1:
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "title": "Multiple write-capable clients",
                        "description": (
                            "Multiple clients issued write "
                            "operations to the same server."
                        ),
                    }
                )

            if asset["exception_codes"]:
                findings.append(
                    {
                        "severity": "LOW",
                        "title": "Protocol exceptions detected",
                        "description": (
                            "Modbus exception responses "
                            "were observed."
                        ),
                    }
                )

            if asset["invalid_function_codes"]:
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "title": "Invalid function codes detected",
                        "description": (
                            "Non-public or malformed Modbus "
                            "function codes were detected."
                        ),
                    }
                )

            return findings

    def _process_adu( self,asset,adu,direction,client_ip=None,):
        if len(adu) < 8:
            asset["invalid_adus"] += 1
            return

        protocol_id = int.from_bytes(adu[2:4], "big")
        declared_length = int.from_bytes(adu[4:6], "big")
        expected_total = 6 + declared_length

        if (
            protocol_id != 0
            or declared_length < 2
            or expected_total != len(adu)
        ):
            asset["invalid_adus"] += 1
            return

        unit_id = adu[6]
        pdu = adu[7:]
        raw_function_code = pdu[0]
        is_exception = bool(raw_function_code & 0x80)
        base_function_code = raw_function_code & 0x7F

        if base_function_code not in MODBUS_PUBLIC_FUNCTION_CODES:
            asset["invalid_function_codes"][raw_function_code] += 1
            asset["invalid_adus"] += 1
            return

        if not self._valid_pdu_shape(
            base_function_code,
            pdu,
            direction,
            is_exception,
        ):
            asset["invalid_adus"] += 1
            return

        asset["decoded_adus"] += 1
        asset["unit_ids"].add(unit_id)
        asset["function_codes"][base_function_code] += 1
        
        WRITE_FUNCTIONS = {0x05, 0x06, 0x0F, 0x10}

        if (
            direction == "request"
            and base_function_code in WRITE_FUNCTIONS
        ):
            asset["write_function_count"] += 1

            if client_ip:
                asset["write_clients"].add(client_ip)
        if is_exception:
            asset["exception_function_codes"][raw_function_code] += 1
            if len(pdu) >= 2:
                asset["exception_codes"][pdu[1]] += 1
            return

        if direction == "response":
            self._parse_identification(asset, pdu)

    @staticmethod
    def _valid_pdu_shape(function_code, pdu, direction, is_exception):
        if is_exception:
            return len(pdu) == 2

        if direction == "request":
            if function_code in {0x01, 0x02, 0x03, 0x04, 0x05, 0x06}:
                return len(pdu) == 5
            if function_code == 0x07:
                return len(pdu) == 1
            if function_code == 0x08:
                return len(pdu) >= 5
            if function_code in {0x0B, 0x0C, 0x11}:
                return len(pdu) == 1
            if function_code in {0x0F, 0x10}:
                if len(pdu) < 6:
                    return False
                return len(pdu) == 6 + pdu[5]
            if function_code in {0x14, 0x15}:
                return len(pdu) >= 2 and len(pdu) == 2 + pdu[1]
            if function_code == 0x16:
                return len(pdu) == 7
            if function_code == 0x17:
                if len(pdu) < 10:
                    return False
                return len(pdu) == 10 + pdu[9]
            if function_code == 0x18:
                return len(pdu) == 3
            if function_code == 0x2B:
                return len(pdu) >= 3
            return False

        if function_code in {0x01, 0x02, 0x03, 0x04}:
            return len(pdu) >= 2 and len(pdu) == 2 + pdu[1]
        if function_code in {0x05, 0x06}:
            return len(pdu) == 5
        if function_code == 0x07:
            return len(pdu) == 2
        if function_code == 0x08:
            return len(pdu) >= 5
        if function_code == 0x0B:
            return len(pdu) == 5
        if function_code == 0x0C:
            return len(pdu) >= 2 and len(pdu) == 2 + pdu[1]
        if function_code in {0x0F, 0x10}:
            return len(pdu) == 5
        if function_code == 0x11:
            return len(pdu) >= 2 and len(pdu) == 2 + pdu[1]
        if function_code in {0x14, 0x15}:
            return len(pdu) >= 2 and len(pdu) == 2 + pdu[1]
        if function_code == 0x16:
            return len(pdu) == 7
        if function_code == 0x17:
            return len(pdu) >= 2 and len(pdu) == 2 + pdu[1]
        if function_code == 0x18:
            if len(pdu) < 3:
                return False
            byte_count = int.from_bytes(pdu[1:3], "big")
            return len(pdu) == 3 + byte_count
        if function_code == 0x2B:
            return len(pdu) >= 3
        return False

    @staticmethod
    def _parse_identification(asset, pdu):
        # FC 43 / MEI 14: Read Device Identification response.
        if len(pdu) >= 7 and pdu[0] == 0x2B and pdu[1] == 0x0E:
            number_of_objects = pdu[6]
            offset = 7
            for _ in range(number_of_objects):
                if offset + 2 > len(pdu):
                    break
                object_id = pdu[offset]
                object_length = pdu[offset + 1]
                offset += 2
                if offset + object_length > len(pdu):
                    break
                asset["device_id_objects"][object_id] = pdu[
                    offset:offset + object_length
                ]
                offset += object_length

        # FC 17: Report Server ID response.
        elif len(pdu) >= 2 and pdu[0] == 0x11:
            byte_count = pdu[1]
            value = pdu[2:2 + byte_count]
            if value:
                asset["server_id"] = value

    @staticmethod
    def _function_details(asset):
        return [
            {
                "code": code,
                "hex": f"0x{code:02X}",
                "name": MODBUS_FUNCTION_NAMES.get(code, "unknown"),
                "count": asset["function_codes"][code],
            }
            for code in sorted(asset["function_codes"])
        ]

    @staticmethod
    def _exception_details(asset):
        return [
            {
                "code": code,
                "hex": f"0x{code:02X}",
                "name": MODBUS_EXCEPTION_CODES.get(code, "unknown"),
                "count": asset["exception_codes"][code],
            }
            for code in sorted(asset["exception_codes"])
        ]

    def finalize(self, context):
        output = {}

        for ip_address, asset in sorted(self.assets.items()):
            identification = self.resolver.resolve_modbus(
                objects=asset["device_id_objects"],
                server_id=asset["server_id"],
            )
            risk_score = self._risk_score(asset)
            risk_level = self._risk_level(risk_score)
            security_findings = self._security_findings(asset)    


            output[ip_address] = {
                "ip": ip_address,
                "port": MODBUS_PORT,
                "role": "modbus_server_candidate",
                "macs": sorted(asset["macs"]),
                "clients": sorted(asset["clients"]),
                "unit_ids": sorted(asset["unit_ids"]),
                "function_codes": sorted(asset["function_codes"]),
                "function_code_details": self._function_details(asset),
                "exception_function_codes": [
                    {
                        "code": code,
                        "hex": f"0x{code:02X}",
                        "base_function_code": code & 0x7F,
                        "count": asset["exception_function_codes"][code],
                    }
                    for code in sorted(asset["exception_function_codes"])
                ],
                "exception_codes": self._exception_details(asset),
                "invalid_function_codes": [
                    {
                        "code": code,
                        "hex": f"0x{code:02X}",
                        "count": asset["invalid_function_codes"][code],
                    }
                    for code in sorted(asset["invalid_function_codes"])
                ],
                "requests": asset["requests"],
                "responses": asset["responses"],
                "decoded_adus": asset["decoded_adus"],
                "invalid_adus": asset["invalid_adus"],
                "first_seen": asset["first_seen"],
                "last_seen": asset["last_seen"],
                "confidence_modbus": (
                    100 if asset["decoded_adus"] else 35
                ),
                "identification": identification,
            }

        context.protocol_results[self.plugin_id] = {
            "passive_only": True,
            "asset_count": len(output),
            "assets": output,
            "stream_statistics": self.tcp_stream_stats(),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "write_function_count": asset["write_function_count"],
            "write_clients": sorted(asset["write_clients"]),
            "security_findings": security_findings,
        }
