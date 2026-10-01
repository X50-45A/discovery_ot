from collections import defaultdict
from datetime import datetime


def now_iso():

    return (
        datetime.now()
        .astimezone()
        .isoformat(
            timespec="seconds"
        )
    )


class DiscoveryContext:

    def __init__(
        self,
        network=None,
        quiet=False,
    ):
        self.network = network
        self.quiet = quiet

        self.protocol_results = (
            defaultdict(dict)
        )

        self.correlated_assets = {}

        self.statistics = {
            "packets_total": 0,
            "packets_ipv4": 0,
            "packets_tcp": 0,
        }

        self.started_at = now_iso()

    def as_dict(
        self,
        plugin_metadata,
    ):

        return {
            "generated_at":
                now_iso(),

            "started_at":
                self.started_at,

            "network": (
                str(self.network)
                if self.network
                else "AUTO_DETECTION"
            ),

            "network_mode": (
                "manual"
                if self.network
                else "automatic"
            ),

            "passive_only":
                True,

            "available_protocols":
                plugin_metadata,

            "statistics":
                self.statistics,

            "protocols":
                dict(
                    self.protocol_results
                ),

            "correlated_asset_count":
                len(
                    self.correlated_assets
                ),

            "correlated_assets":
                self.correlated_assets,
        }