from dataclasses import dataclass, field

@dataclass
class AssetFingerprint:

    ip: str | None = None

    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None

    order_numbers: list[str] = field(
        default_factory=list
    )

    protocols: list[str] = field(
        default_factory=list
    )

    confidence: int = 0

    metadata: dict = field(
        default_factory=dict
    )