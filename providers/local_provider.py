import json
from pathlib import Path

from providers.base_provider import (
    VulnerabilityProvider
)


class LocalProvider(
    VulnerabilityProvider
):

    name = "local"

    def __init__(self, db_file):

        self.db = []

        path = Path(db_file)

        if path.exists():

            self.db = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

    def search(
        self,
        vendor=None,
        model=None,
        firmware=None,
        order_numbers=None,
    ):

        findings = []

        #
        # Order Number Match
        #
        if order_numbers:

            for order in order_numbers:

                for item in self.db:

                    if (
                        item.get(
                            "order_number"
                        )
                        == order
                    ):

                        findings.append(
                            {
                                **item,
                                "match_type":
                                    "order_number",
                                "confidence":
                                    75,
                            }
                        )

        #
        # Model Match
        #
        if not findings and model:

            for item in self.db:

                if (
                    item.get(
                        "model",
                        ""
                    ).lower()
                    ==
                    model.lower()
                ):

                    findings.append(
                        {
                            **item,
                            "match_type":
                                "model",
                            "confidence":
                                50,
                        }
                    )

        #
        # Vendor Match
        #
        if (
            not findings
            and vendor
        ):

            for item in self.db:

                if (
                    item.get(
                        "vendor",
                        ""
                    ).lower()
                    ==
                    vendor.lower()
                ):

                    findings.append(
                        {
                            **item,
                            "match_type":
                                "vendor",
                            "confidence":
                                25,
                        }
                    )

        return findings