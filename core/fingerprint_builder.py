from core.asset_fingerprint import AssetFingerprint

class FingerprintBuilder:


    @staticmethod
    def from_correlated(asset):

        ips = (
            asset.get(
                "ips",
                [],
            )
            or []
        )

        order_numbers = (
            asset.get(
                "order_numbers",
                [],
            )
            or []
        )

        vendor = asset.get(
            "vendor"
        )

        model = asset.get(
            "model"
        )

        firmware = asset.get(
            "firmware"
        )

        metadata = dict(
            asset.get(
                "metadata",
                {},
            )
            or {}
        )

        metadata.update({
            "asset_type":
                asset.get(
                    "asset_type"
                ),

            "macs":
                asset.get(
                    "macs",
                    [],
                ),

            "hostname":
                asset.get(
                    "hostname"
                ),

            "correlation_score":
                asset.get(
                    "correlation_score",
                    0,
                ),

            "correlation_confidence":
                asset.get(
                    "correlation_confidence",
                    0,
                ),

            "correlation_reasons":
                asset.get(
                    "correlation_reasons",
                    [],
                ),

            "sources":
                asset.get(
                    "sources",
                    [],
                ),
        })

        for evidence in (
            asset.get(
                "evidence",
                {},
            )
            or {}
        ).values():

            fingerprint = (
                evidence.get(
                    "fingerprint",
                    {},
                )
                or {}
            )

            evidence_metadata = (
                fingerprint.get(
                    "metadata",
                    {},
                )
                or {}
            )

            for key in (
                "product_name",
                "family",
                "search_terms",
                "system_description",
                "station_name",
                "device_type",
            ):

                if (
                    key not in metadata
                    and evidence_metadata.get(key)
                ):
                    metadata[key] = (
                        evidence_metadata[key]
                    )

            if (
                "system_description"
                not in metadata
                and evidence.get(
                    "system_description"
                )
            ):
                metadata[
                    "system_description"
                ] = evidence[
                    "system_description"
                ]

        return AssetFingerprint(
            ip=(
                ips[0]
                if ips
                else None
            ),
            vendor=vendor,
            model=model,
            firmware=firmware,
            order_numbers=order_numbers,
            protocols=(
                asset.get(
                    "protocols",
                    [],
                )
                or []
            ),
            confidence=max(
                FingerprintBuilder._confidence(
                    vendor,
                    model,
                    firmware,
                    order_numbers,
                ),
                asset.get(
                    "correlation_confidence",
                    0,
                ),
            ),
            metadata=metadata,
        )


    @staticmethod
    def from_modbus(asset):

        identification = (
            asset.get("identification", {})
            or {}
        )

        return AssetFingerprint(

            ip=asset.get("ip"),

            vendor=identification.get(
                "vendor"
            ),

            model=identification.get(
                "model"
            ),

            firmware=identification.get(
                "firmware"
            ),

            order_numbers=[],

            protocols=["modbus_tcp"],

            confidence=FingerprintBuilder._confidence(
                identification.get("vendor"),
                identification.get("model"),
                identification.get("firmware"),
                [],
            )
        )

    @staticmethod
    def from_s7(asset):

        identification = (
            asset.get("identification", {})
            or {}
        )

        products = (
            identification.get(
                "product_or_module",
                []
            )
            or []
        )

        versions = (
            identification.get(
                "firmware_or_versions",
                []
            )
            or []
        )

        order_numbers = (
            identification.get(
                "order_numbers",
                []
            )
            or []
        )

        return AssetFingerprint(

            ip=asset.get("ip"),

            vendor=identification.get(
                "vendor"
            ),

            model=(
                products[0]
                if products
                else None
            ),

            firmware=(
                versions[0]
                if versions
                else None
            ),

            order_numbers=order_numbers,

            protocols=["s7comm"],

            confidence=FingerprintBuilder._confidence(
                identification.get("vendor"),
                products[0] if products else None,
                versions[0] if versions else None,
                order_numbers,
            ),

        )

    @staticmethod
    def from_profinet(asset):

        identification = (
            asset.get("identification", {})
            or {}
        )

        ips = asset.get(
            "ip_addresses",
            [],
        )

        vendor = (
            identification.get("vendor")
            if isinstance(
                identification,
                dict,
            )
            else None
        )

        model = (
            identification.get("model")
            if isinstance(
                identification,
                dict,
            )
            else None
        )

        return AssetFingerprint(

            ip=ips[0] if ips else None,

            vendor=vendor,

            model=model,

            firmware=None,

            order_numbers=[],

            protocols=[
                "profinet_dcp"
            ],

            confidence=(
                FingerprintBuilder._confidence(
                    vendor,
                    model,
                    None,
                    [],
                )
            ),
        )

    @staticmethod
    def from_mqtts(asset):
        return AssetFingerprint(
            ip=asset.get("ip"),
            protocols=["mqtts"],
            confidence=40,
            metadata={
                "sni_names": asset.get("sni_names", []),
                "tls_versions": asset.get("tls_record_versions", []),
            },
        )

    @staticmethod
    def from_dnp3(asset):
        return AssetFingerprint(
            ip=asset.get("ip"),
            protocols=["dnp3"],
            confidence=15,
            metadata={
                "application_functions": asset.get("application_functions", {}),
                "object_groups": asset.get("object_groups", {}),
            },
        )

    @staticmethod
    def from_lldp(asset):

        management_addresses = (
            asset.get(
                "management_addresses",
                [],
            )
            or []
        )

        vendor = asset.get(
            "vendor"
        )

        model = asset.get(
            "model"
        )

        firmware = asset.get(
            "firmware"
        )

        order_numbers = (
            asset.get(
                "order_numbers",
                [],
            )
            or []
        )

        return AssetFingerprint(
            ip=(
                management_addresses[0]
                if management_addresses
                else None
            ),

            vendor=vendor,

            model=model,

            firmware=firmware,

            order_numbers=order_numbers,

            protocols=[
                "lldp"
            ],

            confidence=(
                FingerprintBuilder._confidence(
                    vendor,
                    model,
                    firmware,
                    order_numbers,
                )
            ),

            metadata={
                "system_name":
                    asset.get(
                        "system_name"
                    ),

                "system_description":
                    asset.get(
                        "system_description"
                    ),

                "port_description":
                    asset.get(
                        "port_description"
                    ),

                "management_addresses":
                    management_addresses,

                "chassis_id":
                    asset.get(
                        "chassis_id"
                    ),

                "port_id":
                    asset.get(
                        "port_id"
                    ),

                "frames":
                    asset.get(
                        "frames",
                        0,
                    ),
            },
        )
    
    @staticmethod
    def build(protocol, asset):
        builders = {
            "modbus_tcp": FingerprintBuilder.from_modbus,
            "s7comm": FingerprintBuilder.from_s7,
            "profinet_dcp": FingerprintBuilder.from_profinet,
            "mqtts": FingerprintBuilder.from_mqtts,
            "dnp3": FingerprintBuilder.from_dnp3,
            "lldp": FingerprintBuilder.from_lldp,
            "correlated_asset": FingerprintBuilder.from_correlated,
        }
        fn = builders.get(protocol)
        return fn(asset) if fn else None

    @staticmethod
    def _confidence(
        vendor,
        model,
        firmware,
        order_numbers=None,
    ):

        score = 0

        if vendor:
            score += 20

        if order_numbers:
            score += 50

        if model:
            score += 20

        if firmware:
            score += 10

        return min(score, 100)
