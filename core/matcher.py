from packaging.version import Version

def _match(
    self,
    asset,
    rule,
):

    if (
        rule.vendor
        and asset.vendor
        != rule.vendor
    ):
        return False

    if (
        rule.model
        and asset.model
        != rule.model
    ):
        return False

    if (
        rule.protocols
        and not any(
            p in asset.protocols
            for p in rule.protocols
        )
    ):
        return False

    return True