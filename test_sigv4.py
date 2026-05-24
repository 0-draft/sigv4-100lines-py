"""Deterministic SigV4 test against the AWS-published `get-vanilla` test vector.

Test vector source:
    https://github.com/saibotsivad/aws-sig-v4-test-suite (mirror of the
    Apache 2.0 licensed test files originally distributed by AWS).

Uses the canonical AWS example credentials (fake, do not contact AWS):
    Access Key: AKIDEXAMPLE
    Secret Key: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY

This test imports the algorithm functions from sigv4.py, so it actually
exercises the code shipped in the repo (not a separate re-implementation).
"""

import hashlib

from sigv4 import (
    build_canonical_request,
    build_string_to_sign,
    derive_signing_key,
    sign,
)


ACCESS_KEY = "AKIDEXAMPLE"
SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
REGION = "us-east-1"
SERVICE = "service"
AMZ_DATE = "20150830T123600Z"
DATE_STAMP = "20150830"

REQUEST_METHOD = "GET"
REQUEST_URI = "/"
REQUEST_QUERY = ""
REQUEST_HEADERS = {
    "host": "example.amazonaws.com",
    "x-amz-date": AMZ_DATE,
}
REQUEST_PAYLOAD = ""

EXPECTED_CANONICAL_REQUEST = (
    "GET\n"
    "/\n"
    "\n"
    "host:example.amazonaws.com\n"
    "x-amz-date:20150830T123600Z\n"
    "\n"
    "host;x-amz-date\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

EXPECTED_STRING_TO_SIGN = (
    "AWS4-HMAC-SHA256\n"
    "20150830T123600Z\n"
    "20150830/us-east-1/service/aws4_request\n"
    "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
)

EXPECTED_SIGNATURE = (
    "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
)

EXPECTED_AUTHORIZATION = (
    "AWS4-HMAC-SHA256 "
    "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
    "SignedHeaders=host;x-amz-date, "
    f"Signature={EXPECTED_SIGNATURE}"
)


def main():
    canonical_request, signed_headers = build_canonical_request(
        REQUEST_METHOD, REQUEST_URI, REQUEST_QUERY, REQUEST_HEADERS, REQUEST_PAYLOAD
    )
    assert canonical_request == EXPECTED_CANONICAL_REQUEST, (
        f"canonical_request mismatch\ngot:\n{canonical_request!r}\n\n"
        f"expected:\n{EXPECTED_CANONICAL_REQUEST!r}"
    )

    string_to_sign, credential_scope = build_string_to_sign(
        AMZ_DATE, DATE_STAMP, REGION, SERVICE, canonical_request
    )
    assert string_to_sign == EXPECTED_STRING_TO_SIGN, (
        f"string_to_sign mismatch\ngot:\n{string_to_sign!r}\n\n"
        f"expected:\n{EXPECTED_STRING_TO_SIGN!r}"
    )

    signing_key = derive_signing_key(SECRET_KEY, DATE_STAMP, REGION, SERVICE)
    signature = sign(signing_key, string_to_sign)
    assert signature == EXPECTED_SIGNATURE, (
        f"signature mismatch\ngot:      {signature}\nexpected: {EXPECTED_SIGNATURE}"
    )

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    assert authorization == EXPECTED_AUTHORIZATION, (
        f"authorization mismatch\ngot:      {authorization}\n"
        f"expected: {EXPECTED_AUTHORIZATION}"
    )

    print("OK: get-vanilla SigV4 test vector matches.")
    print(f"  canonical_request hash: {hashlib.sha256(canonical_request.encode()).hexdigest()}")
    print(f"  signature             : {signature}")


if __name__ == "__main__":
    main()
