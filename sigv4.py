"""SigV4 from scratch, no external deps. Calls STS GetCallerIdentity.
Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (+ optional AWS_SESSION_TOKEN), run `python3 sigv4.py`.
"""

import datetime
import hashlib
import hmac
import os
import urllib.error
import urllib.request

ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
SECRET_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
SESSION_TOKEN = os.environ.get("AWS_SESSION_TOKEN")

REGION = "us-east-1"
SERVICE = "sts"
HOST = "sts.amazonaws.com"
ENDPOINT = f"https://{HOST}/"
METHOD = "POST"
CONTENT_TYPE = "application/x-www-form-urlencoded"
PAYLOAD = "Action=GetCallerIdentity&Version=2011-06-15"


def hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


now = datetime.datetime.now(datetime.timezone.utc)
amz_date = now.strftime("%Y%m%dT%H%M%SZ")
date_stamp = now.strftime("%Y%m%d")

# Canonical Request
payload_hash = hashlib.sha256(PAYLOAD.encode()).hexdigest()
base_headers = f"content-type:{CONTENT_TYPE}\nhost:{HOST}\nx-amz-date:{amz_date}\n"
if SESSION_TOKEN:
    canonical_headers = base_headers + f"x-amz-security-token:{SESSION_TOKEN}\n"
    signed_headers = "content-type;host;x-amz-date;x-amz-security-token"
else:
    canonical_headers = base_headers
    signed_headers = "content-type;host;x-amz-date"

canonical_request = (
    f"{METHOD}\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
)

# String to Sign
credential_scope = f"{date_stamp}/{REGION}/{SERVICE}/aws4_request"
string_to_sign = (
    f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
    f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
)

# Signing Key (HMAC 4-step chain)
k_date = hmac_sha256(("AWS4" + SECRET_KEY).encode(), date_stamp)
k_region = hmac_sha256(k_date, REGION)
k_service = hmac_sha256(k_region, SERVICE)
k_signing = hmac_sha256(k_service, "aws4_request")

# Signature
signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

# Authorization header
authorization = (
    f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{credential_scope}, "
    f"SignedHeaders={signed_headers}, Signature={signature}"
)

http_headers = {
    "Content-Type": CONTENT_TYPE,
    "Host": HOST,
    "X-Amz-Date": amz_date,
    "Authorization": authorization,
}
if SESSION_TOKEN:
    http_headers["X-Amz-Security-Token"] = SESSION_TOKEN

req = urllib.request.Request(
    ENDPOINT, data=PAYLOAD.encode(), method=METHOD, headers=http_headers,
)
try:
    with urllib.request.urlopen(req) as res:
        print(res.read().decode())
except urllib.error.HTTPError as e:
    print("HTTPError:", e.code)
    print(e.read().decode())
