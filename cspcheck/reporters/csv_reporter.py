import os
import pandas as pd
from datetime import datetime, timezone
from typing import List
from cspcheck.core.findings import Finding

def write_csv(findings: List[Finding], out_dir: str = "./reports", prefix: str = "cspcheck") -> str:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(out_dir, f"{prefix}_report_{ts}.csv")
    rows = [f.to_dict() for f in findings]
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)
    return path

