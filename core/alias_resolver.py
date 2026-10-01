import json
from pathlib import Path


class AliasResolver:

    def __init__(self, alias_file):

        self.aliases = {}

        path = Path(alias_file)

        if path.exists():

            self.aliases = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

    def resolve(self, fingerprint):

        for order in getattr(
            fingerprint,
            "order_numbers",
            [],
        ):

            alias = self.aliases.get(
                order
            )

            if alias:
                return alias

        if fingerprint.model:

            alias = self.aliases.get(
                fingerprint.model
            )

            if alias:
                return alias

        return None