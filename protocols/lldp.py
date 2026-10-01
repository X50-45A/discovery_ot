from collections import defaultdict
import re

from scapy.all import Ether, Raw

from core.base import ProtocolPlugin


class LldpPlugin(ProtocolPlugin):

    plugin_id = "lldp"
    display_name = "LLDP"
    description = (
        "Inventario pasivo LLDP con "
        "fingerprinting OT."
    )

    version = "2.0"

    bpf_filter = "ether proto 0x88cc"

    def __init__(self, config=None):

        super().__init__(config)

        self.emitters = defaultdict(
            lambda: {
                "frames": 0,

                "chassis_id": None,
                "port_id": None,

                "system_name": None,
                "system_description": None,
                "port_description": None,

                "management_addresses": [],

                "vendor": None,
                "model": None,

                "raw_tlvs": [],
            }
        )

    def process_packet(
        self,
        packet,
        context,
    ):

        if (
            not packet.haslayer(Ether)
            or packet[Ether].type != 0x88CC
        ):
            return

        source = packet[Ether].src

        asset = self.emitters[source]

        asset["frames"] += 1

        if not packet.haslayer(Raw):
            return

        payload = bytes(packet[Raw])

        if len(asset["raw_tlvs"]) < 3:
            asset["raw_tlvs"].append(
                payload.hex()
            )

        self._parse_lldp(
            payload,
            asset,
        )

    def _parse_lldp(
        self,
        payload,
        asset,
    ):

        offset = 0

        while offset + 2 <= len(payload):

            header = int.from_bytes(
                payload[offset:offset + 2],
                "big",
            )

            tlv_type = (
                header >> 9
            )

            tlv_length = (
                header & 0x01FF
            )

            offset += 2

            if (
                offset + tlv_length
                > len(payload)
            ):
                break

            value = payload[
                offset:
                offset + tlv_length
            ]

            offset += tlv_length

            #
            # End of LLDPDU
            #
            if tlv_type == 0:
                break

            #
            # Port Description
            #
            elif tlv_type == 4:

                asset[
                    "port_description"
                ] = self._safe_text(
                    value
                )

            #
            # System Name
            #
            elif tlv_type == 5:

                asset[
                    "system_name"
                ] = self._safe_text(
                    value
                )

            #
            # System Description
            #
            elif tlv_type == 6:

                asset[
                    "system_description"
                ] = self._safe_text(
                    value
                )

            #
            # Management Address
            #
            elif tlv_type == 8:

                address = (
                    self._parse_mgmt(
                        value
                    )
                )

                if (
                    address
                    and address not in
                    asset[
                        "management_addresses"
                    ]
                ):
                    asset[
                        "management_addresses"
                    ].append(
                        address
                    )

    @staticmethod
    def _safe_text(data):

        try:

            return data.decode(
                "utf-8",
                errors="ignore",
            ).strip()

        except Exception:

            return None

    @staticmethod
    def _parse_mgmt(value):

        try:

            addr_len = value[0]

            if addr_len < 2:
                return None

            subtype = value[1]

            if subtype == 1:

                return ".".join(
                    str(x)
                    for x in value[
                        2:6
                    ]
                )

        except Exception:
            pass

        return None

    @staticmethod
    def _detect_vendor(text):

        if not text:
            return None

        text = text.lower()

        vendors = {
            "siemens":
                "Siemens",

            "moxa":
                "Moxa",

            "phoenix":
                "Phoenix Contact",

            "rockwell":
                "Rockwell",

            "allen-bradley":
                "Rockwell",

            "schneider":
                "Schneider Electric",

            "hirschmann":
                "Hirschmann",
        }

        for pattern, vendor in (
            vendors.items()
        ):

            if pattern in text:
                return vendor

        return None

    @staticmethod
    def _detect_model(text):

        if not text:
            return None

        patterns = [

            r"EDS[- ]?[0-9A-Z]+",

            r"SCALANCE[- ]?[A-Z0-9]+",

            r"FL SWITCH[ A-Z0-9-]+",

            r"RS[0-9]{3,}",

            r"ICS[- ]?[0-9A-Z]+",
        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
                re.I,
            )

            if match:
                return match.group(0)

        return None

    def finalize(self, context):

        for asset in self.emitters.values():

            text = " ".join(

                filter(
                    None,
                    [

                        asset.get(
                            "system_name"
                        ),

                        asset.get(
                            "system_description"
                        ),
                    ],
                )
            )

            asset["vendor"] = (
                self._detect_vendor(
                    text
                )
            )

            asset["model"] = (
                self._detect_model(
                    text
                )
            )
            
            
            asset["firmware"] = (
                self._detect_firmware(text)
            )

            asset["order_numbers"] = (
                self._detect_order_number(text)
            )


        context.protocol_results[
            self.plugin_id
        ] = {

            "emitter_count":
                len(self.emitters),

            "emitters":
                dict(
                    sorted(
                        self.emitters.items()
                    )
                ),
        }


    @staticmethod
    def _detect_order_number(text):

        if not text:
            return []

        matches = re.findall(
            r"6ES7[\s-]*[0-9A-Z-]+",
            text,
            re.I,
        )

        return list(
            dict.fromkeys(matches)
        )
    @staticmethod
    def _detect_firmware(text):

        if not text:
            return None

        match = re.search(
            r"FW:\s*([A-Za-z0-9.\-]+)",
            text,
            re.I,
        )

        if match:
            return match.group(1)

        return None