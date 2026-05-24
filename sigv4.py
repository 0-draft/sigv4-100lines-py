"""SigV4 from scratch, no external deps. Calls STS GetCallerIdentity.
Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (+ optional AWS_SESSION_TOKEN), run `python3 sigv4.py`.
"""

import datetime
import hashlib
import hmac
import os
import urllib.error
import urllib.request


def hmac_sha256(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def build_canonical_request(method, uri, query, headers, payload):
    sorted_keys = sorted(headers)
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted_keys)
    signed_headers = ";".join(sorted_keys)
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    cr = f"{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    return cr, signed_headers


def build_string_to_sign(amz_date, date_stamp, region, service, canonical_request):
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    cr_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
    return f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{cr_hash}", scope


def derive_signing_key(secret_key, date_stamp, region, service):
    k_date = hmac_sha256(("AWS4" + secret_key).encode(), date_stamp)
    k_region = hmac_sha256(k_date, region)
    k_service = hmac_sha256(k_region, service)
    return hmac_sha256(k_service, "aws4_request")


def sign(signing_key, string_to_sign):
    return hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()


def main():
    access_key = os.environ["AWS_ACCESS_KEY_ID"]
    secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    session_token = os.environ.get("AWS_SESSION_TOKEN")

    region, service, host = "us-east-1", "sts", "sts.amazonaws.com"
    method = "POST"
    content_type = "application/x-www-form-urlencoded"
    payload = "Action=GetCallerIdentity&Version=2011-06-15"

    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    headers = {"content-type": content_type, "host": host, "x-amz-date": amz_date}
    if session_token:
        headers["x-amz-security-token"] = session_token

    cr, signed_headers = build_canonical_request(method, "/", "", headers, payload)
    sts, scope = build_string_to_sign(amz_date, date_stamp, region, service, cr)
    signature = sign(derive_signing_key(secret_key, date_stamp, region, service), sts)

    auth = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    http_headers = {
        "Content-Type": content_type,
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": auth,
    }
    if session_token:
        http_headers["X-Amz-Security-Token"] = session_token

    req = urllib.request.Request(
        f"https://{host}/", data=payload.encode(), method=method, headers=http_headers,
    )
    try:
        with urllib.request.urlopen(req) as res:
            print(res.read().decode())
    except urllib.error.HTTPError as e:
        print("HTTPError:", e.code)
        print(e.read().decode())


if __name__ == "__main__":
    main()
