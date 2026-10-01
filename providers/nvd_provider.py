import re
import time

import requests

from .base_provider import VulnerabilityProvider


class NvdProvider(VulnerabilityProvider):

    name = "nvd"

    URL = (
        "https://services.nvd.nist.gov/"
        "rest/json/cves/2.0"
    )

    def __init__(
        self,
        api_key=None,
        timeout=20,
        max_results=50,
    ):
        self.api_key = api_key
        self.timeout = timeout
        self.max_results = max_results

    def search(
        self,
        vendor=None,
        model=None,
        firmware=None,
        order_numbers=None,
        metadata=None,
    ):
        metadata = metadata or {}
        order_numbers = order_numbers or []

        queries = self._build_queries(
            vendor=vendor,
            model=model,
            order_numbers=order_numbers,
            metadata=metadata,
        )

        if not queries:
            return self._empty_result(
                reason="insufficient_fingerprint"
            )

        attempts = []
        candidates = []

        for query in queries:

            print(
                f"[NVD QUERY] {query}"
            )

            try:
                data = self._request(
                    query
                )

            except requests.RequestException as error:
                attempts.append({
                    "query": query,
                    "error": str(error),
                })
                continue

            total = data.get(
                "totalResults",
                0,
            )

            print(
                f"[NVD RESULTS] {total}"
            )

            attempts.append({
                "query": query,
                "total_results": total,
            })

            if total <= 0:
                continue

            vulnerabilities = data.get(
                "vulnerabilities",
                [],
            )

            candidates.extend(
                vulnerabilities
            )

            if self._is_specific_query(
                query=query,
                model=model,
                order_numbers=order_numbers,
            ):
                break

            if not self.api_key:
                time.sleep(0.7)

        deduplicated = self._deduplicate(
            candidates
        )

        filtered = self._filter_candidates(
            vulnerabilities=deduplicated,
            vendor=vendor,
            model=model,
            firmware=firmware,
            order_numbers=order_numbers,
            metadata=metadata,
        )

        return {
            "queries_attempted": attempts,
            "candidate_count": len(
                deduplicated
            ),
            "totalResults": len(
                filtered
            ),
            "vulnerabilities": filtered,
            "match_status": (
                "candidate_matches"
                if filtered
                else "no_relevant_matches"
            ),
        }

    def _request(self, query):

        headers = {}

        if self.api_key:
            headers["apiKey"] = (
                self.api_key
            )

        response = requests.get(
            self.URL,
            params={
                "keywordSearch": query,
                "resultsPerPage":
                    self.max_results,
            },
            headers=headers,
            timeout=self.timeout,
        )

        response.raise_for_status()

        return response.json()

    @classmethod
    def _build_queries(
        cls,
        vendor,
        model,
        order_numbers,
        metadata,
    ):
        queries = []

        product_name = metadata.get(
            "product_name"
        )

        if product_name:
            queries.append(
                product_name
            )

        search_terms = metadata.get(
            "search_terms",
            [],
        ) or []

        queries.extend(
            search_terms
        )

        family = metadata.get(
            "family"
        )

        if family:
            queries.append(
                family
            )

        description = metadata.get(
            "system_description",
            "",
        )

        lldp_identity = (
            cls._extract_lldp_identity(
                description
            )
        )

        extracted_model = (
            lldp_identity.get(
                "model"
            )
        )

        extracted_family = (
            lldp_identity.get(
                "family"
            )
        )

        extracted_order = (
            lldp_identity.get(
                "order_number"
            )
        )

        if vendor and extracted_model:
            queries.append(
                f"{vendor} {extracted_model}"
            )

        if vendor and extracted_family:
            queries.append(
                f"{vendor} {extracted_family}"
            )

        if extracted_model:
            queries.append(
                extracted_model
            )

        if extracted_family:
            queries.append(
                extracted_family
            )

        if vendor and model:
            queries.append(
                f"{vendor} {model}"
            )

        if model:
            queries.append(
                model
            )

        for order in order_numbers:
            if order:
                queries.append(
                    order
                )

        if extracted_order:
            queries.append(
                extracted_order
            )

        normalized_queries = []
        seen = set()

        for query in queries:

            if not isinstance(
                query,
                str,
            ):
                continue

            query = re.sub(
                r"\s+",
                " ",
                query,
            ).strip()

            if not query:
                continue

            query_key = query.casefold()

            if query_key in seen:
                continue

            seen.add(
                query_key
            )

            normalized_queries.append(
                query
            )

        return normalized_queries

    @staticmethod
    def _extract_lldp_identity(
        description,
    ):
        identity = {
            "family": None,
            "model": None,
            "order_number": None,
        }

        if not description:
            return identity

        order_match = re.search(
            r"\b6ES7\s+[0-9A-Z-]+\b",
            description,
            re.IGNORECASE,
        )

        if order_match:
            identity["order_number"] = (
                order_match.group(0)
                .strip()
            )

        cpu_smart_match = re.search(
            r"\bCPU[- ]?200\s+SMART\b",
            description,
            re.IGNORECASE,
        )

        if cpu_smart_match:
            identity["model"] = (
                "CPU 200 SMART"
            )

            identity["family"] = (
                "SIMATIC S7-200 SMART"
            )

            return identity

        s7_family_match = re.search(
            r"\bS7[- ]?"
            r"(200|300|400|1200|1500)\b",
            description,
            re.IGNORECASE,
        )

        if s7_family_match:
            family_number = (
                s7_family_match.group(1)
            )

            identity["family"] = (
                f"SIMATIC S7-{family_number}"
            )

        cpu_model_match = re.search(
            r"\bCPU[- ]?[0-9A-Z]+"
            r"(?:[- ][0-9A-Z/]+)*\b",
            description,
            re.IGNORECASE,
        )

        if cpu_model_match:
            identity["model"] = (
                cpu_model_match.group(0)
                .strip()
            )

        return identity

    @classmethod
    def _filter_candidates(
        cls,
        vulnerabilities,
        vendor,
        model,
        firmware,
        order_numbers,
        metadata,
    ):
        relevant = []

        description = metadata.get(
            "system_description",
            "",
        )

        lldp_identity = (
            cls._extract_lldp_identity(
                description
            )
        )

        family = (
            metadata.get("family")
            or lldp_identity.get("family")
        )

        detected_model = (
            model
            or metadata.get("model")
            or lldp_identity.get("model")
        )

        match_terms = []

        if vendor:
            match_terms.append(
                vendor
            )

        if detected_model:
            match_terms.append(
                detected_model
            )

        if family:
            match_terms.append(
                family
            )

        match_terms.extend(
            order_numbers
            or []
        )

        extracted_order = (
            lldp_identity.get(
                "order_number"
            )
        )

        if extracted_order:
            match_terms.append(
                extracted_order
            )

        alias_terms = metadata.get(
            "search_terms",
            [],
        ) or []

        match_terms.extend(
            alias_terms
        )

        normalized_vendor = (
            cls._normalize(vendor)
            if vendor
            else None
        )

        normalized_terms = []

        for term in match_terms:

            if not term:
                continue

            normalized = (
                cls._normalize(term)
            )

            if normalized:
                normalized_terms.append(
                    normalized
                )

        normalized_terms = list(
            dict.fromkeys(
                normalized_terms
            )
        )

        for item in vulnerabilities:

            cve = item.get(
                "cve",
                {},
            )

            searchable_text = (
                cls._cve_searchable_text(
                    cve
                )
            )

            normalized_text = (
                cls._normalize(
                    searchable_text
                )
            )

            matched_terms = [
                term
                for term in normalized_terms
                if term in normalized_text
            ]

            specific_matches = [
                term
                for term in matched_terms
                if (
                    not normalized_vendor
                    or term
                    != normalized_vendor
                )
            ]

            if not specific_matches:
                continue

            enriched_item = dict(
                item
            )

            enriched_item[
                "correlation"
            ] = {
                "matched_terms":
                    specific_matches,

                "firmware_observed":
                    firmware,

                "status": (
                    "product_and_firmware_observed"
                    if firmware
                    else "product_match"
                ),

                "note": (
                    "El CVE menciona el producto, "
                    "modelo, familia o referencia "
                    "detectada. Debe validarse la "
                    "versión afectada antes de "
                    "clasificarlo como confirmado."
                ),
            }

            relevant.append(
                enriched_item
            )

        return relevant

    @staticmethod
    def _cve_searchable_text(cve):

        parts = [
            cve.get(
                "id",
                "",
            ),
            cve.get(
                "sourceIdentifier",
                "",
            ),
        ]

        descriptions = cve.get(
            "descriptions",
            [],
        ) or []

        for description in descriptions:

            parts.append(
                description.get(
                    "value",
                    "",
                )
            )

        configurations = cve.get(
            "configurations",
            [],
        ) or []

        parts.append(
            str(configurations)
        )

        return " ".join(
            parts
        )

    @staticmethod
    def _normalize(value):

        value = str(
            value
        ).casefold()

        value = re.sub(
            r"[^a-z0-9]+",
            " ",
            value,
        )

        return re.sub(
            r"\s+",
            " ",
            value,
        ).strip()

    @staticmethod
    def _deduplicate(
        vulnerabilities,
    ):
        result = []
        seen = set()

        for item in vulnerabilities:

            cve_id = (
                item.get(
                    "cve",
                    {},
                ).get(
                    "id"
                )
            )

            if not cve_id:
                continue

            if cve_id in seen:
                continue

            seen.add(
                cve_id
            )

            result.append(
                item
            )

        return result

    @staticmethod
    def _is_specific_query(
        query,
        model,
        order_numbers,
    ):
        normalized_query = (
            query.casefold()
        )

        if (
            model
            and model.casefold()
            in normalized_query
        ):
            return True

        for order in (
            order_numbers
            or []
        ):

            if (
                order.casefold()
                in normalized_query
            ):
                return True

        return False

    @staticmethod
    def _empty_result(reason):

        return {
            "queries_attempted": [],
            "candidate_count": 0,
            "totalResults": 0,
            "vulnerabilities": [],
            "match_status": reason,
        }