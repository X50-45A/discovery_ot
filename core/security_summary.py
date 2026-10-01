class SecuritySummary:

    INVENTORY_KEYS = (
        "assets",
        "servers",
        "devices",
        "outstations",
        "brokers",
        "emitters",
    )

    COUNT_KEYS = (
        "asset_count",
        "server_count",
        "device_count",
        "outstation_count",
        "broker_count",
        "emitter_count",
    )

    MAX_CVES = 5
    MAX_DESCRIPTION_LENGTH = 180

    @classmethod
    def _inventory(cls, protocol_data):

        for key in cls.INVENTORY_KEYS:

            if key in protocol_data:
                return protocol_data[key]

        return {}

    @classmethod
    def _count(cls, protocol_data):

        for key in cls.COUNT_KEYS:

            if key in protocol_data:
                return protocol_data[key]

        return 0

    @staticmethod
    def _risk(asset):

        score = asset.get(
            "risk_score"
        )

        if score is None:
            return "UNKNOWN", 0

        return (
            asset.get(
                "risk_level",
                "UNKNOWN",
            ),
            score,
        )

    @staticmethod
    def _description(
        cve,
        preferred_language="es",
    ):

        descriptions = (
            cve.get(
                "descriptions",
                [],
            )
            or []
        )

        for description in descriptions:

            if (
                description.get("lang")
                == preferred_language
            ):
                return description.get(
                    "value"
                )

        return None

    @staticmethod
    def _extract_cvss(cve):

        metrics = (
            cve.get(
                "metrics",
                {},
            )
            or {}
        )

        metric_keys = (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        )

        for key in metric_keys:

            entries = (
                metrics.get(
                    key,
                    [],
                )
                or []
            )

            for entry in entries:

                cvss_data = (
                    entry.get(
                        "cvssData",
                        {},
                    )
                    or {}
                )

                score = cvss_data.get(
                    "baseScore"
                )

                severity = (
                    cvss_data.get(
                        "baseSeverity"
                    )
                    or entry.get(
                        "baseSeverity"
                    )
                )

                if (
                    score is not None
                    or severity
                ):
                    return (
                        severity,
                        score,
                    )

        return None, None

    @classmethod
    def _append_fingerprint(
        cls,
        lines,
        asset,
    ):

        fingerprint = (
            asset.get(
                "fingerprint",
                {},
            )
            or {}
        )

        vendor = fingerprint.get(
            "vendor"
        )

        model = fingerprint.get(
            "model"
        )

        firmware = fingerprint.get(
            "firmware"
        )

        order_numbers = (
            fingerprint.get(
                "order_numbers",
                [],
            )
            or []
        )

        metadata = (
            fingerprint.get(
                "metadata",
                {},
            )
            or {}
        )

        if vendor or model:

            lines.append(
                f"    Fingerprint: "
                f"{vendor or '?'} / "
                f"{model or '?'}"
            )

        if firmware:

            lines.append(
                f"    Firmware: "
                f"{firmware}"
            )

        if order_numbers:

            lines.append(
                "    Order Number: "
                + ", ".join(
                    order_numbers
                )
            )

        product_name = metadata.get(
            "product_name"
        )

        if product_name:

            lines.append(
                f"    Product: "
                f"{product_name}"
            )

        confidence = fingerprint.get(
            "confidence"
        )

        if confidence is not None:

            lines.append(
                f"    Fingerprint confidence: "
                f"{confidence}/100"
            )

    @classmethod
    def _append_security_findings(
        cls,
        lines,
        asset,
    ):

        findings = (
            asset.get(
                "security_findings",
                [],
            )
            or []
        )

        for finding in findings:

            title = finding.get(
                "title",
                "Unnamed finding",
            )

            severity = finding.get(
                "severity"
            )

            if severity:

                lines.append(
                    f"    - [{severity}] "
                    f"{title}"
                )

            else:

                lines.append(
                    f"    - {title}"
                )

    @classmethod
    def _append_deduplicated_vulnerabilities(
    cls,
    lines,
    asset,
    ):
        vulnerabilities = (
            asset.get(
                "deduplicated_vulnerabilities",
                [],
            )
            or []
        )

        if not vulnerabilities:
            return

        lines.append(
            f"    Unique vulnerabilities: "
            f"{len(vulnerabilities)}"
        )

        for vulnerability in vulnerabilities[
            :cls.MAX_CVES
        ]:

            cve_id = vulnerability.get(
                "cve",
                "UNKNOWN",
            )

            severity = vulnerability.get(
                "severity",
                "UNKNOWN",
            )

            cvss = vulnerability.get(
                "cvss"
            )

            line = (
                f"      - {cve_id}"
            )

            if severity != "UNKNOWN":
                line += (
                    f" [{severity}]"
                )

            if cvss is not None:
                line += (
                    f" CVSS {cvss}"
                )

            lines.append(
                line
            )

            sources = (
                vulnerability.get(
                    "sources",
                    [],
                )
                or []
            )

            if sources:

                lines.append(
                    "        Sources: "
                    + ", ".join(
                        sources
                    )
                )

            advisories = (
                vulnerability.get(
                    "advisories",
                    [],
                )
                or []
            )

            if advisories:

                lines.append(
                    "        Advisories: "
                    + ", ".join(
                        advisories
                    )
                )

            status = vulnerability.get(
                "status"
            )

            confidence = vulnerability.get(
                "confidence"
            )

            if status:

                status_line = (
                    f"        Status: "
                    f"{status}"
                )

                if confidence is not None:
                    status_line += (
                        f" ({confidence}/100)"
                    )

                lines.append(
                    status_line
                )

            matched_terms = (
                vulnerability.get(
                    "matched_terms",
                    [],
                )
                or []
            )

            if matched_terms:

                lines.append(
                    "        Match: "
                    + ", ".join(
                        matched_terms
                    )
                )

            description = vulnerability.get(
                "description"
            )

            if description:

                description = (
                    str(description)
                    .replace(
                        "\r",
                        " ",
                    )
                    .replace(
                        "\n",
                        " ",
                    )
                )

                description = " ".join(
                    description.split()
                )

                if (
                    len(description)
                    > cls.MAX_DESCRIPTION_LENGTH
                ):

                    description = (
                        description[
                            :cls.MAX_DESCRIPTION_LENGTH
                            - 3
                        ]
                        + "..."
                    )

                lines.append(
                    f"        {description}"
                )

        hidden = (
            len(vulnerabilities)
            - cls.MAX_CVES
        )

        if hidden > 0:

            lines.append(
                f"      ... y {hidden} "
                f"vulnerabilidad(es) adicional(es) "
                f"en el JSON"
            )


    @classmethod
    def _append_vulnerabilities(
        cls,
        lines,
        asset,
    ):

        provider_findings = (
            asset.get(
                "vulnerability_findings",
                [],
            )
            or []
        )

        for provider_finding in provider_findings:

            provider = provider_finding.get(
                "provider",
                "unknown",
            )

            provider_error = provider_finding.get(
                "error"
            )

            if provider_error:

                lines.append(
                    f"    Vulnerability provider error "
                    f"({provider}): "
                    f"{provider_error}"
                )

                continue

            result = (
                provider_finding.get(
                    "result"
                )
                or {}
            )

            if not isinstance(
                result,
                dict,
            ):
                continue

            response = (
                result.get(
                    "response"
                )
                or result
            )

            if not isinstance(
                response,
                dict,
            ):
                response = {}

            vulnerabilities = (
                result.get(
                    "vulnerabilities"
                )
                or response.get(
                    "vulnerabilities"
                )
                or []
            )

            total_results = result.get(
                "totalResults"
            )

            if total_results is None:

                total_results = response.get(
                    "totalResults",
                    len(vulnerabilities),
                )

            if not vulnerabilities:
                continue

            lines.append(
                f"    Vulnerabilities "
                f"({provider}): "
                f"{total_results}"
            )

            query_used = result.get(
                "query_used"
            )

            if query_used:

                lines.append(
                    f"      Query: "
                    f"{query_used}"
                )

            else:

                attempts = (
                    result.get(
                        "queries_attempted",
                        [],
                    )
                    or []
                )

                successful_queries = [
                    item.get("query")
                    for item in attempts
                    if (
                        item.get(
                            "total_results",
                            0,
                        )
                        > 0
                    )
                ]

                successful_queries = [
                    query
                    for query in successful_queries
                    if query
                ]

                if successful_queries:

                    lines.append(
                        "      Queries with results: "
                        + ", ".join(
                            successful_queries
                        )
                    )

            for item in vulnerabilities[
                :cls.MAX_CVES
            ]:

                cve = (
                    item.get(
                        "cve",
                        {},
                    )
                    or {}
                )

                cve_id = cve.get(
                    "id"
                )

                if not cve_id:
                    continue

                severity, cvss = (
                    cls._extract_cvss(
                        cve
                    )
                )

                cve_line = (
                    f"      - {cve_id}"
                )

                if severity:

                    cve_line += (
                        f" [{severity}]"
                    )

                if cvss is not None:

                    cve_line += (
                        f" CVSS {cvss}"
                    )

                lines.append(
                    cve_line
                )

                correlation = (
                    item.get(
                        "correlation",
                        {},
                    )
                    or {}
                )

                matched_terms = (
                    correlation.get(
                        "matched_terms",
                        [],
                    )
                    or []
                )

                if matched_terms:

                    lines.append(
                        "        Match: "
                        + ", ".join(
                            matched_terms
                        )
                    )

                description = (
                    cls._description(
                        cve,
                        preferred_language="es",
                    )
                    or cls._description(
                        cve,
                        preferred_language="en",
                    )
                )

                if description:

                    description = (
                        description
                        .replace(
                            "\r",
                            " ",
                        )
                        .replace(
                            "\n",
                            " ",
                        )
                    )

                    description = " ".join(
                        description.split()
                    )

                    if (
                        len(description)
                        > cls.MAX_DESCRIPTION_LENGTH
                    ):

                        description = (
                            description[
                                :cls.MAX_DESCRIPTION_LENGTH
                                - 3
                            ]
                            + "..."
                        )

                    lines.append(
                        f"        {description}"
                    )

            hidden_count = (
                len(vulnerabilities)
                - cls.MAX_CVES
            )

            if hidden_count > 0:

                lines.append(
                    f"      ... y "
                    f"{hidden_count} "
                    f"resultado(s) adicional(es) "
                    f"en el JSON"
                )

    @classmethod
    def build(
        cls,
        protocol_results,
        correlated_assets=None,
    ):
        correlated_assets = (
            correlated_assets
            or {}
        )

        lines = []

        lines.append("=" * 40)
        lines.append(
            "Discovery_OT Security Summary"
        )
        lines.append("=" * 40)

        asset_count = sum(
            cls._count(
                protocol_data
            )
            for protocol_data
            in protocol_results.values()
        )

        lines.append(
            f"Assets discovered : "
            f"{asset_count}"
        )

        lines.append("")

        #
        # Resultados individuales por protocolo
        #
        for (
            protocol,
            protocol_data,
        ) in protocol_results.items():

            inventory = cls._inventory(
                protocol_data
            )

            lines.append(
                f"[{protocol}]"
            )

            protocol_error = (
                protocol_data.get(
                    "error"
                )
            )

            if protocol_error:

                lines.append(
                    f"  Protocol error: "
                    f"{protocol_error}"
                )

                lines.append("")
                continue

            if not inventory:

                lines.append(
                    "  No assets detected"
                )

                lines.append("")
                continue

            for (
                asset_id,
                asset,
            ) in inventory.items():

                risk_level, risk_score = (
                    cls._risk(
                        asset
                    )
                )

                lines.append(
                    f"  {asset_id} "
                    f"({risk_level}/{risk_score})"
                )

                processing_error = (
                    asset.get(
                        "security_processing_error"
                    )
                )

                if processing_error:

                    lines.append(
                        f"    Processing error: "
                        f"{processing_error}"
                    )

                cls._append_fingerprint(
                    lines,
                    asset,
                )

                cls._append_security_findings(
                    lines,
                    asset,
                )

                #
                # Las CVEs por protocolo normalmente
                # estarán vacías tras la correlación.
                # Se mantiene por compatibilidad.
                #
                cls._append_vulnerabilities(
                    lines,
                    asset,
                )

                lines.append("")

        #
        # Activos físicos correlacionados
        #
        if correlated_assets:

            lines.append("=" * 40)
            lines.append(
                "Correlated Assets"
            )
            lines.append("=" * 40)
            lines.append("")

            lines.append(
                f"Correlated assets : "
                f"{len(correlated_assets)}"
            )

            lines.append("")

            for (
                asset_id,
                asset,
            ) in correlated_assets.items():

                risk_level, risk_score = (
                    cls._risk(
                        asset
                    )
                )

                lines.append(
                    f"  {asset_id} "
                    f"({risk_level}/{risk_score})"
                )

                ips = (
                    asset.get(
                        "ips",
                        [],
                    )
                    or []
                )

                if ips:

                    lines.append(
                        "    IPs: "
                        + ", ".join(
                            str(ip)
                            for ip in ips
                        )
                    )

                macs = (
                    asset.get(
                        "macs",
                        [],
                    )
                    or []
                )

                if macs:

                    lines.append(
                        "    MACs: "
                        + ", ".join(
                            str(mac)
                            for mac in macs
                        )
                    )

                protocols = (
                    asset.get(
                        "protocols",
                        [],
                    )
                    or asset.get(
                        "sources",
                        [],
                    )
                    or []
                )

                if protocols:

                    lines.append(
                        "    Protocols: "
                        + ", ".join(
                            str(protocol)
                            for protocol
                            in protocols
                        )
                    )

                asset_type = asset.get(
                    "asset_type"
                )

                if asset_type:

                    lines.append(
                        f"    Asset type: "
                        f"{asset_type}"
                    )

                hostname = asset.get(
                    "hostname"
                )

                if hostname:

                    lines.append(
                        f"    Hostname: "
                        f"{hostname}"
                    )

                #
                # Fingerprint correlacionado
                #
                fingerprint = (
                    asset.get(
                        "fingerprint",
                        {},
                    )
                    or {}
                )

                vendor = (
                    fingerprint.get(
                        "vendor"
                    )
                    or asset.get(
                        "vendor"
                    )
                )

                model = (
                    fingerprint.get(
                        "model"
                    )
                    or asset.get(
                        "model"
                    )
                )

                firmware = (
                    fingerprint.get(
                        "firmware"
                    )
                    or asset.get(
                        "firmware"
                    )
                )

                order_numbers = (
                    fingerprint.get(
                        "order_numbers",
                        [],
                    )
                    or asset.get(
                        "order_numbers",
                        [],
                    )
                    or []
                )

                confidence = (
                    fingerprint.get(
                        "confidence"
                    )
                )

                fingerprint_metadata = (
                    fingerprint.get(
                        "metadata",
                        {},
                    )
                    or {}
                )

                if vendor or model:

                    lines.append(
                        f"    Fingerprint: "
                        f"{vendor or '?'} / "
                        f"{model or '?'}"
                    )

                if firmware:

                    lines.append(
                        f"    Firmware: "
                        f"{firmware}"
                    )

                if order_numbers:

                    lines.append(
                        "    Order Number: "
                        + ", ".join(
                            str(order)
                            for order
                            in order_numbers
                        )
                    )

                product_name = (
                    fingerprint_metadata.get(
                        "product_name"
                    )
                )

                if product_name:

                    lines.append(
                        f"    Product: "
                        f"{product_name}"
                    )

                family = (
                    fingerprint_metadata.get(
                        "family"
                    )
                )

                if family:

                    lines.append(
                        f"    Product family: "
                        f"{family}"
                    )

                if confidence is not None:

                    lines.append(
                        f"    Fingerprint confidence: "
                        f"{confidence}/100"
                    )

                #
                # Información de correlación
                #
                correlation_score = (
                    asset.get(
                        "correlation_score"
                    )
                )

                correlation_confidence = (
                    asset.get(
                        "correlation_confidence"
                    )
                )

                correlation_reasons = (
                    asset.get(
                        "correlation_reasons",
                        [],
                    )
                    or []
                )

                if correlation_score is not None:

                    lines.append(
                        f"    Correlation score: "
                        f"{correlation_score}"
                    )

                if (
                    correlation_confidence
                    is not None
                ):

                    lines.append(
                        f"    Correlation confidence: "
                        f"{correlation_confidence}/100"
                    )

                if correlation_reasons:

                    lines.append(
                        "    Correlation reasons: "
                        + ", ".join(
                            str(reason)
                            for reason
                            in correlation_reasons
                        )
                    )

                assessment_error = (
                    asset.get(
                        "assessment_error"
                    )
                )

                if assessment_error:

                    lines.append(
                        f"    Assessment error: "
                        f"{assessment_error}"
                    )

                #
                # Findings combinados de LLDP,
                # S7Comm, Modbus, etc.
                #
                cls._append_security_findings(
                    lines,
                    asset,
                )

                #
                # CVEs calculadas una sola vez
                # sobre el activo correlacionado.
                #
                cls._append_vulnerabilities(
                    lines,
                    asset,
                )

                lines.append("")

        return "\n".join(
            lines
        )
