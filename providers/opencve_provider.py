from .base_provider import VulnerabilityProvider
import requests


class OpenCveProvider(VulnerabilityProvider):

    name = "opencve"

    def __init__(self, token):
        self.token = token

    def search(
        self,
        vendor=None,
        model=None,
        firmware=None,
        order_numbers=None,
    ):

        terms = []

        if vendor:
            terms.append(vendor)

        if model:
            terms.append(model)

        if order_numbers:
            terms.extend(order_numbers)

        query = " ".join(terms)

        if not query:
            return []

        response = requests.get(
            "https://app.opencve.io/api/cve",
            params={
                "search": query,
            },
            headers={
                "Authorization":
                    f"Bearer {self.token}",
            },
            timeout=20,
        )

        response.raise_for_status()

        return response.json()