from dataclasses import dataclass, asdict
from typing import Literal, Dict, Any

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

@dataclass
class Finding:
    provider: Literal["aws", "azure"]
    account: str
    resource_type: str
    resource_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        base = asdict(self)
        for k, v in list(base.get("metadata", {}).items()):
            base[f"meta_{k}"] = v
        base.pop("metadata", None)
        return base

