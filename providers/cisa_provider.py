import csv
import re
from pathlib import Path

from .base_provider import VulnerabilityProvider


class CisaIcsProvider(VulnerabilityProvider):

    name = "cisa_ics"

    def __init__(self, csv_file):

        self.csv_file = Path(
            csv_file
        )

        self.records = []
        self.columns = []

        if not self.csv_file.is_file():
            return

        with self.csv_file.open(
            "r",
            encoding="utf-8-sig",
            errors="replace",
            newline="",
        ) as file_handle:

            reader = csv.DictReader(
                file_handle
            )

            self.columns = (
                reader.fieldnames
                or []
            )

            self.records = list(
                reader
            )

    def search(
        self,
        vendor=None,
        model=None,
        firmware=None,
        order_numbers=None,
        metadata=None,
    ):

        metadata = (
            metadata
            or {}
        )

        queries = self._build_queries(
            vendor=vendor,
            model=model,
            order_numbers=order_numbers,
            metadata=metadata,
        )

        if not queries:

            return {
                "totalResults": 0,
                "matches": [],
                "queries_attempted": [],
                "dataset": str(
                    self.csv_file
                ),
            }

        matches = []
        seen = set()

        for record in self.records:

            searchable_text = (
                self._record_text(
                    record
                )
            )

            normalized_record = (
                self._normalize(
                    searchable_text
                )
            )

            matched_terms = []

            for query in queries:

                normalized_query = (
                    self._normalize(
                        query
                    )
                )

                if (
                    normalized_query
                    and normalized_query
                    in normalized_record
                ):

                    matched_terms.append(
                        query
                    )

            if not matched_terms:
                continue

            record_key = self._record_key(
                record
            )

            if record_key in seen:
                continue

            seen.add(
                record_key
            )

            matches.append({
                "record": record,
                "matched_terms": matched_terms,
                "match_status": (
                    "product_match"
                ),
                "firmware_observed": firmware,
            })

        return {
            "totalResults": len(
                matches
            ),
            "matches": matches,
            "queries_attempted": queries,
            "dataset": str(
                self.csv_file
            ),
            "columns": self.columns,
        }

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

        family = metadata.get(
            "family"
        )

        if family:

            queries.append(
                family
            )

        queries.extend(
            metadata.get(
                "search_terms",
                [],
            )
            or []
        )

        system_description = metadata.get(
            "system_description"
        )

        if system_description:

            queries.extend(
                cls._description_terms(
                    system_description
                )
            )

        if vendor and model:

            queries.append(
                f"{vendor} {model}"
            )

        if model:

            queries.append(
                model
            )

        queries.extend(
            order_numbers
            or []
        )

        result = []
        seen = set()

        for query in queries:

            if not query:
                continue

            cleaned = re.sub(
                r"\s+",
                " ",
                str(query),
            ).strip()

            key = cleaned.casefold()

            if (
                not cleaned
                or key in seen
            ):
                continue

            seen.add(
                key
            )

            result.append(
                cleaned
            )

        return result

    @staticmethod
    def _description_terms(
        description,
    ):

        terms = []

        if re.search(
            r"S7[- ]?200\s+SMART",
            description,
            re.IGNORECASE,
        ):

            terms.extend([
                "SIMATIC S7-200 SMART",
                "S7-200 SMART",
                "CPU 200 SMART",
            ])

        return terms

    @staticmethod
    def _record_text(record):

        return " ".join(
            str(value)
            for value
            in record.values()
            if value
        )

    @staticmethod
    def _record_key(record):

        preferred_keys = (
            "Advisory",
            "Advisory ID",
            "CVE",
            "CVE ID",
            "Title",
            "Product",
        )

        values = []

        for key in preferred_keys:

            value = record.get(
                key
            )

            if value:

                values.append(
                    str(value)
                )

        if values:

            return "|".join(
                values
            )

        return repr(
            sorted(
                record.items()
            )
        )

    @staticmethod
    def _normalize(value):

        normalized = (
            str(value)
            .casefold()
        )

        normalized = re.sub(
            r"[^a-z0-9]+",
            " ",
            normalized,
        )

        return re.sub(
            r"\s+",
            " ",
            normalized,
        ).strip()