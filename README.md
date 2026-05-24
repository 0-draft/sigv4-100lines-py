# sigv4-100lines-py

AWS Signature Version 4 (SigV4) in under 100 lines of pure Python, no external dependencies. Calls `STS GetCallerIdentity` end-to-end, so you can see your own request authenticated by AWS without `boto3` or `requests` in the loop.

Companion code for the dev.to article [SigV4 を 100 行の Python で書いて AWS を叩くハンズオン](https://dev.to/kanywst/aws-sigv4-from-scratch-hands-on).

## What this is

A self-contained `sigv4.py` that:

- Builds a Canonical Request from scratch
- Builds a String to Sign with the credential scope
- Derives the Signing Key via the 4-step HMAC chain (`date -> region -> service -> aws4_request`)
- Computes the final HMAC-SHA256 Signature
- Assembles the `Authorization` header
- POSTs to `https://sts.amazonaws.com/` and prints the response

Supports both long-lived IAM User keys (`AKIA...`) and STS temporary credentials (`ASIA...` + `X-Amz-Security-Token`).

## Why it exists

SDKs like `boto3` hide SigV4 behind one method call. Writing it once by hand makes the actual mechanism legible: which bytes get HMAC'd, why the credential scope encodes date/region/service, and what `X-Amz-Security-Token` actually does on the wire.

After this, debugging `SignatureDoesNotMatch` errors stops being magic.

## Files

| File          | Purpose                                                                                      | External deps |
| ------------- | -------------------------------------------------------------------------------------------- | ------------- |
| `sigv4.py`    | The full SigV4 implementation. Calls `STS GetCallerIdentity` and prints the XML response.    | None          |
| `get_temp.py` | Helper to fetch STS temporary credentials with `boto3` and print `export ...` lines.         | `boto3`       |

`sigv4.py` is the star. `get_temp.py` exists only so you can test the `ASIA...` + SessionToken path without writing the temp-credential bootstrap from scratch.

## Prerequisites

- Python 3.10 or newer
- An AWS account
- An IAM User with an Access Key (no policies attached; `GetCallerIdentity` is unauthenticated and works for any IAM identity)

## Run it

### With long-lived IAM User keys

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
python3 sigv4.py
```

Expected output (truncated):

```xml
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/your-user</Arn>
    <UserId>AIDAEXAMPLEUSERID</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  ...
</GetCallerIdentityResponse>
```

### With STS temporary credentials

```bash
# Bootstrap temporary credentials (uses boto3 internally).
pip install boto3
python3 get_temp.py

# Copy-paste the printed export lines into your shell.
export AWS_ACCESS_KEY_ID='ASIA...'
export AWS_SECRET_ACCESS_KEY='...'
export AWS_SESSION_TOKEN='...'

# Now run sigv4.py with the temp credentials.
python3 sigv4.py
```

`sigv4.py` detects `AWS_SESSION_TOKEN` and automatically adds the `X-Amz-Security-Token` header and includes it in `SignedHeaders`.

The response `Arn` now starts with `arn:aws:sts::` (assumed-role / federated) instead of `arn:aws:iam::` (long-lived user). That is the on-the-wire signal that you are using a temporary credential.

## Cost

`STS GetCallerIdentity` is free on every AWS account, no usage tier required. Running the script costs $0.

## Debugging tips

The most common failure mode is `SignatureDoesNotMatch`. Likely causes, in order of frequency:

1. **`SecretAccessKey` is wrong**: re-check the environment variable.
2. **Clock skew**: your local clock is more than 15 minutes off UTC. Sync via NTP.
3. **Canonical Request structure**: an extra/missing newline anywhere breaks the SHA256. Cross-check against the AWS reference.
4. **Header order**: `CanonicalHeaders` must be sorted alphabetically by lowercased header name.
5. **Temporary credential without `x-amz-security-token` in `SignedHeaders`**: easy to miss when adapting the long-lived code path.

When stuck, print the `canonical_request`, `string_to_sign`, and `signature` and compare byte-for-byte against the AWS-documented example values.

## What this does NOT cover

- **SigV4A** (asymmetric SigV4 used for multi-region S3): different algorithm, not in scope here.
- **Presigned URLs**: a variant where the signature rides in the query string instead of headers. Easy to extend `sigv4.py` to do this.
- **Streaming uploads** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`): the chunk-by-chunk variant used by large S3 PUTs.

These are all extensions of the same core. The 4-step chain in `sigv4.py` is the foundation everything else builds on.

## License

MIT
