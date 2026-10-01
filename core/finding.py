from dataclasses import dataclass

@dataclass
class Finding:
    id: str
    severity: str

    title: str
    description: str

    confidence: str

    protocol: str | None = None
    cve: str | None = None