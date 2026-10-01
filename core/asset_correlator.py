from copy import deepcopy


class AssetCorrelator:

    SCORE_MAC = 100
    SCORE_IP = 80
    SCORE_ORDER_NUMBER = 70
    SCORE_HOSTNAME = 30
    SCORE_MODEL = 20
    SCORE_VENDOR = 10

    MERGE_THRESHOLD = 80

    def correlate(
        self,
        protocol_results,
    ):
        candidates = []

        self._ingest_lldp(
            candidates,
            protocol_results.get(
                "lldp",
                {},
            ),
        )

        self._ingest_s7(
            candidates,
            protocol_results.get(
                "s7comm",
                {},
            ),
        )

        self._ingest_modbus(
            candidates,
            protocol_results.get(
                "modbus_tcp",
                {},
            ),
        )

        self._ingest_profinet(
            candidates,
            protocol_results.get(
                "profinet_dcp",
                {},
            ),
        )

        self._ingest_dnp3(
            candidates,
            protocol_results.get(
                "dnp3",
                {},
            ),
        )

        correlated = self._merge_candidates(
            candidates
        )

        return {
            self._asset_id(index, asset): asset
            for index, asset in enumerate(
                correlated,
                start=1,
            )
        }

    def _ingest_lldp(
        self,
        candidates,
        protocol_data,
    ):
        emitters = protocol_data.get(
            "emitters",
            {},
        )

        for mac, device in emitters.items():

            management_addresses = (
                device.get(
                    "management_addresses",
                    [],
                )
                or []
            )

            fingerprint = (
                device.get(
                    "fingerprint",
                    {},
                )
                or {}
            )

            candidate = self._new_candidate(
                source="lldp",
                ip=(
                    management_addresses[0]
                    if management_addresses
                    else fingerprint.get("ip")
                ),
                mac=mac,
                vendor=(
                    fingerprint.get("vendor")
                    or device.get("vendor")
                ),
                model=(
                    fingerprint.get("model")
                    or device.get("model")
                ),
                firmware=(
                    fingerprint.get("firmware")
                    or device.get("firmware")
                ),
                order_numbers=(
                    fingerprint.get(
                        "order_numbers",
                        [],
                    )
                    or device.get(
                        "order_numbers",
                        [],
                    )
                    or []
                ),
                hostname=device.get(
                    "system_name"
                ),
                asset_type=(
                    "network_device"
                    if self._looks_like_switch(device)
                    else "industrial_device"
                ),
                raw=device,
            )

            candidate[
                "management_addresses"
            ] = management_addresses

            candidate["metadata"].update({
                "system_name":
                    device.get("system_name"),

                "system_description":
                    device.get(
                        "system_description"
                    ),

                "port_description":
                    device.get(
                        "port_description"
                    ),

                "chassis_id":
                    device.get("chassis_id"),

                "port_id":
                    device.get("port_id"),
            })

            candidates.append(
                candidate
            )

    def _ingest_s7(
        self,
        candidates,
        protocol_data,
    ):
        servers = protocol_data.get(
            "servers",
            {},
        )

        for ip, device in servers.items():

            identification = (
                device.get(
                    "identification",
                    {},
                )
                or {}
            )

            fingerprint = (
                device.get(
                    "fingerprint",
                    {},
                )
                or {}
            )

            macs = (
                device.get(
                    "macs",
                    [],
                )
                or []
            )

            products = (
                identification.get(
                    "product_or_module",
                    [],
                )
                or []
            )

            versions = (
                identification.get(
                    "firmware_or_versions",
                    [],
                )
                or []
            )

            candidate = self._new_candidate(
                source="s7comm",
                ip=ip,
                mac=(
                    macs[0]
                    if macs
                    else None
                ),
                vendor=(
                    fingerprint.get("vendor")
                    or identification.get("vendor")
                ),
                model=(
                    fingerprint.get("model")
                    or (
                        products[0]
                        if products
                        else None
                    )
                ),
                firmware=(
                    fingerprint.get("firmware")
                    or (
                        versions[0]
                        if versions
                        else None
                    )
                ),
                order_numbers=(
                    fingerprint.get(
                        "order_numbers",
                        [],
                    )
                    or identification.get(
                        "order_numbers",
                        [],
                    )
                    or []
                ),
                hostname=self._s7_hostname(
                    identification
                ),
                asset_type="plc",
                raw=device,
            )

            candidates.append(
                candidate
            )

    def _ingest_modbus(
        self,
        candidates,
        protocol_data,
    ):
        assets = (
            protocol_data.get("assets")
            or protocol_data.get("servers")
            or {}
        )

        for ip, device in assets.items():

            fingerprint = (
                device.get(
                    "fingerprint",
                    {},
                )
                or {}
            )

            identification = (
                device.get(
                    "identification",
                    {},
                )
                or {}
            )

            macs = (
                device.get(
                    "macs",
                    [],
                )
                or []
            )

            candidate = self._new_candidate(
                source="modbus_tcp",
                ip=ip,
                mac=(
                    macs[0]
                    if macs
                    else None
                ),
                vendor=(
                    fingerprint.get("vendor")
                    or identification.get("vendor")
                ),
                model=(
                    fingerprint.get("model")
                    or identification.get("model")
                ),
                firmware=(
                    fingerprint.get("firmware")
                    or identification.get("firmware")
                ),
                order_numbers=(
                    fingerprint.get(
                        "order_numbers",
                        [],
                    )
                    or []
                ),
                hostname=None,
                asset_type="industrial_device",
                raw=device,
            )

            candidates.append(
                candidate
            )

    def _ingest_profinet(
        self,
        candidates,
        protocol_data,
    ):
        devices = protocol_data.get(
            "devices",
            {},
        )

        for mac, device in devices.items():

            fingerprint = (
                device.get(
                    "fingerprint",
                    {},
                )
                or {}
            )

            identification = (
                device.get(
                    "identification",
                    {},
                )
                or {}
            )

            addresses = (
                device.get(
                    "ip_addresses",
                    [],
                )
                or []
            )

            candidate = self._new_candidate(
                source="profinet_dcp",
                ip=(
                    addresses[0]
                    if addresses
                    else fingerprint.get("ip")
                ),
                mac=(
                    device.get("source_mac")
                    or mac
                ),
                vendor=(
                    fingerprint.get("vendor")
                    or identification.get("vendor")
                ),
                model=(
                    fingerprint.get("model")
                    or identification.get("model")
                    or device.get("device_type")
                ),
                firmware=(
                    fingerprint.get("firmware")
                ),
                order_numbers=(
                    fingerprint.get(
                        "order_numbers",
                        [],
                    )
                    or []
                ),
                hostname=(
                    device.get("station_name")
                    or device.get("alias_name")
                ),
                asset_type=self._profinet_type(
                    device
                ),
                raw=device,
            )

            candidates.append(
                candidate
            )

    def _ingest_dnp3(
        self,
        candidates,
        protocol_data,
    ):
        outstations = protocol_data.get(
            "outstations",
            {},
        )

        for ip, device in outstations.items():

            macs = (
                device.get(
                    "macs",
                    [],
                )
                or []
            )

            candidate = self._new_candidate(
                source="dnp3",
                ip=ip,
                mac=(
                    macs[0]
                    if macs
                    else None
                ),
                vendor=None,
                model=None,
                firmware=None,
                order_numbers=[],
                hostname=None,
                asset_type="outstation",
                raw=device,
            )

            candidates.append(
                candidate
            )

    @staticmethod
    def _new_candidate(
        source,
        ip,
        mac,
        vendor,
        model,
        firmware,
        order_numbers,
        hostname,
        asset_type,
        raw,
    ):
        return {
            "ips": (
                [ip]
                if ip
                else []
            ),
            "macs": (
                [mac.lower()]
                if mac
                else []
            ),
            "vendor": vendor,
            "model": model,
            "firmware": firmware,
            "order_numbers": list(
                dict.fromkeys(
                    order_numbers or []
                )
            ),
            "hostname": hostname,
            "asset_type": asset_type,
            "protocols": [source],
            "sources": [source],
            "metadata": {},
            "evidence": {
                source: deepcopy(raw)
            },
            "security_findings": list(
                deepcopy(
                    raw.get(
                        "security_findings",
                        [],
                    )
                    or []
                )
            ),
            "correlation_score": 0,
            "correlation_confidence": 0,
            "correlation_reasons": [],
        }

    def _merge_candidates(
        self,
        candidates,
    ):
        correlated = []

        for candidate in candidates:

            best_target = None
            best_score = 0
            best_reasons = []

            for existing in correlated:

                score, reasons = (
                    self._score(
                        existing,
                        candidate,
                    )
                )

                if score > best_score:
                    best_target = existing
                    best_score = score
                    best_reasons = reasons

            if (
                best_target is not None
                and best_score
                >= self.MERGE_THRESHOLD
            ):
                self._merge(
                    target=best_target,
                    source=candidate,
                    score=best_score,
                    reasons=best_reasons,
                )

            else:
                new_asset = deepcopy(
                    candidate
                )

                new_asset[
                    "correlation_score"
                ] = 0

                new_asset[
                    "correlation_confidence"
                ] = self._identity_confidence(
                    new_asset
                )

                correlated.append(
                    new_asset
                )

        return correlated

    def _score(
        self,
        left,
        right,
    ):
        score = 0
        reasons = []

        left_macs = set(
            self._normalize_mac(mac)
            for mac in left.get(
                "macs",
                [],
            )
            if mac
        )

        right_macs = set(
            self._normalize_mac(mac)
            for mac in right.get(
                "macs",
                [],
            )
            if mac
        )

        if (
            left_macs
            and right_macs
            and left_macs.intersection(
                right_macs
            )
        ):
            score += self.SCORE_MAC

            reasons.append(
                "matching_mac"
            )

        left_ips = set(
            left.get(
                "ips",
                [],
            )
        )

        right_ips = set(
            right.get(
                "ips",
                [],
            )
        )

        if (
            left_ips
            and right_ips
            and left_ips.intersection(
                right_ips
            )
        ):
            score += self.SCORE_IP

            reasons.append(
                "matching_management_ip"
            )

        left_orders = set(
            self._normalize_text(order)
            for order in left.get(
                "order_numbers",
                [],
            )
            if order
        )

        right_orders = set(
            self._normalize_text(order)
            for order in right.get(
                "order_numbers",
                [],
            )
            if order
        )

        if (
            left_orders
            and right_orders
            and left_orders.intersection(
                right_orders
            )
        ):
            score += (
                self.SCORE_ORDER_NUMBER
            )

            reasons.append(
                "matching_order_number"
            )

        left_hostname = (
            self._normalize_text(
                left.get("hostname")
            )
        )

        right_hostname = (
            self._normalize_text(
                right.get("hostname")
            )
        )

        if (
            left_hostname
            and right_hostname
            and left_hostname
            == right_hostname
        ):
            score += self.SCORE_HOSTNAME

            reasons.append(
                "matching_hostname"
            )

        left_model = (
            self._normalize_text(
                left.get("model")
            )
        )

        right_model = (
            self._normalize_text(
                right.get("model")
            )
        )

        if (
            left_model
            and right_model
            and self._models_compatible(
                left_model,
                right_model,
            )
        ):
            score += self.SCORE_MODEL

            reasons.append(
                "compatible_model"
            )

        left_vendor = (
            self._normalize_text(
                left.get("vendor")
            )
        )

        right_vendor = (
            self._normalize_text(
                right.get("vendor")
            )
        )

        if (
            left_vendor
            and right_vendor
            and left_vendor
            == right_vendor
        ):
            score += self.SCORE_VENDOR

            reasons.append(
                "matching_vendor"
            )

        return score, reasons

    def _merge(
        self,
        target,
        source,
        score,
        reasons,
    ):
        target["ips"] = self._merge_lists(
            target.get("ips"),
            source.get("ips"),
        )

        target["macs"] = self._merge_lists(
            target.get("macs"),
            source.get("macs"),
        )

        target[
            "order_numbers"
        ] = self._merge_lists(
            target.get(
                "order_numbers"
            ),
            source.get(
                "order_numbers"
            ),
        )

        target[
            "protocols"
        ] = self._merge_lists(
            target.get("protocols"),
            source.get("protocols"),
        )

        target[
            "sources"
        ] = self._merge_lists(
            target.get("sources"),
            source.get("sources"),
        )

        target[
            "security_findings"
        ] = self._merge_findings(
            target.get(
                "security_findings",
            ),
            source.get(
                "security_findings",
            ),
        )

        target[
            "correlation_reasons"
        ] = self._merge_lists(
            target.get(
                "correlation_reasons"
            ),
            reasons,
        )

        target[
            "correlation_score"
        ] = max(
            target.get(
                "correlation_score",
                0,
            ),
            score,
        )

        target[
            "correlation_confidence"
        ] = min(
            100,
            max(
                target.get(
                    "correlation_confidence",
                    0,
                ),
                score,
            ),
        )

        for field in (
            "vendor",
            "model",
            "firmware",
            "hostname",
        ):
            target[field] = (
                self._choose_value(
                    field=field,
                    current=target.get(field),
                    incoming=source.get(field),
                    current_sources=target.get(
                        "sources",
                        [],
                    ),
                    incoming_sources=source.get(
                        "sources",
                        [],
                    ),
                )
            )

        if (
            target.get("asset_type")
            in (None, "industrial_device")
            and source.get("asset_type")
        ):
            target["asset_type"] = (
                source["asset_type"]
            )

        target[
            "metadata"
        ].update(
            source.get(
                "metadata",
                {},
            )
        )

        target[
            "evidence"
        ].update(
            deepcopy(
                source.get(
                    "evidence",
                    {},
                )
            )
        )

    @staticmethod
    def _choose_value(
        field,
        current,
        incoming,
        current_sources,
        incoming_sources,
    ):
        if not current:
            return incoming

        if not incoming:
            return current

        priority = {
            "s7comm": 100,
            "profinet_dcp": 90,
            "lldp": 80,
            "modbus_tcp": 70,
            "dnp3": 60,
        }

        current_priority = max(
            (
                priority.get(
                    source,
                    0,
                )
                for source
                in current_sources
            ),
            default=0,
        )

        incoming_priority = max(
            (
                priority.get(
                    source,
                    0,
                )
                for source
                in incoming_sources
            ),
            default=0,
        )

        if (
            field == "firmware"
            and incoming
            and not current
        ):
            return incoming

        if (
            incoming_priority
            > current_priority
        ):
            return incoming

        return current

    @staticmethod
    def _merge_lists(
        left,
        right,
    ):
        return list(
            dict.fromkeys(
                list(left or [])
                + list(right or [])
            )
        )

    @staticmethod
    def _merge_findings(
        left,
        right,
    ):
        result = []
        seen = set()

        for finding in (
            list(left or [])
            + list(right or [])
        ):
            key = (
                finding.get("severity"),
                finding.get("title"),
            )

            if key in seen:
                continue

            seen.add(key)
            result.append(
                deepcopy(finding)
            )

        return result

    @staticmethod
    def _normalize_text(value):

        if value is None:
            return None

        normalized = " ".join(
            str(value)
            .casefold()
            .replace("-", " ")
            .replace("_", " ")
            .split()
        )

        return (
            normalized
            if normalized
            else None
        )

    @staticmethod
    def _normalize_mac(value):

        if not value:
            return None

        return (
            value
            .strip()
            .lower()
            .replace("-", ":")
        )

    @staticmethod
    def _models_compatible(
        left,
        right,
    ):
        if left == right:
            return True

        if left in right:
            return True

        if right in left:
            return True

        return False

    @staticmethod
    def _identity_confidence(
        asset,
    ):
        score = 0

        if asset.get("ips"):
            score += 25

        if asset.get("macs"):
            score += 25

        if asset.get("vendor"):
            score += 10

        if asset.get("model"):
            score += 15

        if asset.get("firmware"):
            score += 10

        if asset.get(
            "order_numbers"
        ):
            score += 15

        return min(
            score,
            100,
        )

    @staticmethod
    def _asset_id(
        index,
        asset,
    ):
        if asset.get("ips"):

            normalized_ip = (
                asset["ips"][0]
                .replace(
                    ".",
                    "_",
                )
                .replace(
                    ":",
                    "_",
                )
            )

            return (
                f"asset_{normalized_ip}"
            )

        if asset.get("macs"):

            normalized_mac = (
                asset["macs"][0]
                .replace(
                    ":",
                    ""
                )
            )

            return (
                f"asset_{normalized_mac}"
            )

        return (
            f"asset_{index}"
        )

    @staticmethod
    def _s7_hostname(
        identification,
    ):
        strings = (
            identification.get(
                "observed_strings",
                [],
            )
            or []
        )

        ignored_terms = (
            "cpu",
            "simatic",
            "boot loader",
            "siemens",
            "6es7",
            "s7-",
            "et200",
        )

        for value in strings:

            normalized = (
                str(value)
                .strip()
            )

            if not normalized:
                continue

            lower = (
                normalized.casefold()
            )

            if any(
                term in lower
                for term in ignored_terms
            ):
                continue

            if (
                len(normalized)
                >= 3
                and len(normalized)
                <= 64
            ):
                return normalized

        return None

    @staticmethod
    def _looks_like_switch(
        device,
    ):
        text = " ".join(
            filter(
                None,
                (
                    device.get(
                        "system_name"
                    ),
                    device.get(
                        "system_description"
                    ),
                ),
            )
        ).casefold()

        terms = (
            "switch",
            "scalance x",
            "moxa eds",
            "hirschmann",
            "comware",
            "stratix",
        )

        return any(
            term in text
            for term in terms
        )

    @staticmethod
    def _profinet_type(
        device,
    ):
        roles = set(
            device.get(
                "device_roles",
                [],
            )
            or []
        )

        if "io_controller" in roles:
            return "plc"

        if "io_device" in roles:
            return "io_device"

        return "industrial_device"