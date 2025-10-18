from typing import List
from botocore.exceptions import ClientError
from cspcheck.core.findings import Finding

def s3_public_findings(session) -> List[Finding]:
    s3 = session.client("s3")
    sts = session.client("sts")
    account = sts.get_caller_identity()["Account"]

    findings: List[Finding] = []
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        acl_public = False
        policy_public = False
        bpa_off = False

        # ACL check
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                acl_public = True

        # Policy check
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            if "\"Principal\":\"*\"" in pol.get("Policy", ""):
                policy_public = True
        except ClientError:
            pass  # no policy

        # Block Public Access check
        try:
            bpa = s3.get_public_access_block(Bucket=name)
            cfg = bpa["PublicAccessBlockConfiguration"]
            if not all(cfg.get(k, False) for k in cfg):
                bpa_off = True
        except ClientError:
            bpa_off = True  # no BPA set

        if acl_public or policy_public or bpa_off:
            findings.append(Finding(
                provider="aws",
                account=account,
                resource_type="s3",
                resource_id=name,
                title="S3 bucket potentially public",
                severity="HIGH",
                description="Bucket has public ACL/policy or Block Public Access disabled.",
                remediation="Enable Block Public Access; remove public ACLs and wildcard principals; use presigned URLs.",
                metadata={"acl_public": acl_public, "policy_public": policy_public, "bpa_off": bpa_off},
            ))
    return findings

