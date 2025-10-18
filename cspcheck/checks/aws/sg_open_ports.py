from typing import List, Iterable
from cspcheck.core.findings import Finding

# Sensitive ports to check for public access
SENSITIVE_PORTS = {22, 3389, 5432, 3306, 80, 443}

def sg_open_findings(session, sensitive_ports: Iterable[int] = SENSITIVE_PORTS) -> List[Finding]:
    ec2 = session.client("ec2")
    sts = session.client("sts")
    account = sts.get_caller_identity()["Account"]

    resp = ec2.describe_security_groups()
    findings: List[Finding] = []

    for sg in resp.get("SecurityGroups", []):
        gid = sg.get("GroupId")
        gname = sg.get("GroupName")

        for perm in sg.get("IpPermissions", []):
            from_p = perm.get("FromPort")
            to_p = perm.get("ToPort")
            ports = set()

            # Sometimes ranges are used — collect all defined ports
            if isinstance(from_p, int):
                ports.add(from_p)
            if isinstance(to_p, int):
                ports.add(to_p)

            cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
            ipv6 = [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]

            open_to_world = any(c in ("0.0.0.0/0", "::/0") for c in cidrs + ipv6)
            sensitive_hit = bool(ports & set(sensitive_ports))

            if open_to_world and sensitive_hit:
                findings.append(Finding(
                    provider="aws",
                    account=account,
                    resource_type="security-group",
                    resource_id=gid,
                    title="Security Group with 0.0.0.0/0 on sensitive ports",
                    severity="CRITICAL",
                    description=f"Open ingress on ports {sorted(list(ports & set(sensitive_ports)))}",
                    remediation="Restrict access to known IP ranges, use bastion hosts, or VPN.",
                    metadata={
                        "group_name": gname,
                        "ports": sorted(list(ports)),
                        "cidrs": cidrs,
                        "ipv6": ipv6
                    },
                ))
    return findings

