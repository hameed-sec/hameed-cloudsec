from typing import Iterable
from datetime import datetime
from sqlmodel import SQLModel, Field, create_engine, Session, select

class FindingRow(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=datetime.utcnow, index=True)
    provider: str
    account: str
    resource_type: str
    resource_id: str
    title: str
    severity: str
    description: str
    remediation: str
    meta_json: str

_engine = create_engine("sqlite:///cspcheck.db", echo=False)

def init_db():
    SQLModel.metadata.create_all(_engine)

def save_findings(rows: Iterable[dict]):
    # rows are dicts from Finding.to_dict()
    with Session(_engine) as s:
        for r in rows:
            meta = {k[len("meta_"):]: v for k,v in r.items() if k.startswith("meta_")}
            base = {k: v for k,v in r.items() if not k.startswith("meta_")}
            fr = FindingRow(
                provider=base.get("provider",""),
                account=base.get("account",""),
                resource_type=base.get("resource_type",""),
                resource_id=base.get("resource_id",""),
                title=base.get("title",""),
                severity=base.get("severity",""),
                description=base.get("description",""),
                remediation=base.get("remediation",""),
                meta_json=__import__("json").dumps(meta),
            )
            s.add(fr)
        s.commit()

def list_findings(limit: int = 200):
    with Session(_engine) as s:
        stmt = select(FindingRow).order_by(FindingRow.ts.desc()).limit(limit)
        return s.exec(stmt).all()
