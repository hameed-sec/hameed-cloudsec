import boto3
from typing import Optional

def aws_session(profile: Optional[str] = None):
    """
    Return a boto3.Session using an optional AWS named profile.
    Region will be picked up from the profile or env (AWS_REGION).
    """
    if profile:
        return boto3.session.Session(profile_name=profile)
    return boto3.session.Session()

