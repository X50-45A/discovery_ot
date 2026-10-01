class VulnerabilityProvider:

    name = "base"

    def search(
        self,
        vendor=None,
        model=None,
        firmware=None,
        order_numbers=None,
    ):
        raise NotImplementedError