"""
Fetch STS temporary credentials and print them as `export ...` lines.

Used only as a helper for sigv4.py to test the ASIA... + SessionToken path.
This script DOES depend on boto3 because it just bootstraps the temporary
credentials. sigv4.py itself stays dependency-free.

Usage:
    export AWS_ACCESS_KEY_ID="AKIA..."
    export AWS_SECRET_ACCESS_KEY="..."
    python3 get_temp.py
    # then copy-paste the printed `export ...` lines into your shell.
"""

import boto3

sts = boto3.client("sts")
res = sts.get_session_token(DurationSeconds=3600)
c = res["Credentials"]
print(f"export AWS_ACCESS_KEY_ID='{c['AccessKeyId']}'")
print(f"export AWS_SECRET_ACCESS_KEY='{c['SecretAccessKey']}'")
print(f"export AWS_SESSION_TOKEN='{c['SessionToken']}'")
