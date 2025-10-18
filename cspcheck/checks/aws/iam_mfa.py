from datetime import datetime, timezone
from typing import List
from cspcheck.core.findings import Finding

def iam_mfa_key_findings(session, max_age_days: int = 90) -> List[Finding]:
    iam = session.client("iam")
    sts = session.client("sts")
    account = sts.get_caller_identity()["Account"]

    findings: List[Finding] = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for u in page.get("Users", []):
            uname = u["UserName"]

            # MFA check
            mfas = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfas:
                findings.append(Finding(
                    provider="aws",
                    account=account,
                    resource_type="iam-user",
                    resource_id=uname,
                    title="IAM user without MFA",
                    severity="HIGH",
                    description="User has no MFA device registered.",
                    remediation="Enforce MFA via IAM/SCP or migrate to IAM Identity Center (SSO).",
                    metadata={},
                ))

            # Access key age check
            aks = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
            for k in aks:
                created = k["CreateDate"]
                age_days = (datetime.now(timezone.utc) - created).days
                if k["Status"] == "Active" and age_days > max_age_days:
                    findings.append(Finding(
                        provider="aws",
                        account=account,
                        resource_type="iam-access-key",
                        resource_id=k["AccessKeyId"],
                        title=f"Access key older than {max_age_days} days",
                        severity="MEDIUM",
                        description=f"Key age {age_days} days for user {uname}.",
                        remediation="Rotate access keys regularly; prefer role-based access.",
                        metadata={"age_days": age_days, "user": uname},
                    ))
    return findings
