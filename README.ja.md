# sigv4-100lines-py

[English](README.md) | **日本語**

[![test](https://github.com/0-draft/sigv4-100lines-py/actions/workflows/test.yml/badge.svg)](https://github.com/0-draft/sigv4-100lines-py/actions/workflows/test.yml)

AWS Signature Version 4 (SigV4) を 100 行未満の Python で実装したもの。外部依存ゼロ、`boto3` も `requests` も使わずに `STS GetCallerIdentity` を end-to-end で叩く。

アルゴリズムの正当性は push のたびに `test_sigv4.py` が検証する。AWS が公開してる [`get-vanilla` SigV4 test vector](https://github.com/saibotsivad/aws-sig-v4-test-suite) を、`sigv4.py` から export してる関数そのものに食わせて期待値と byte-exact 比較する仕組み。

## 何をしているか

自己完結した `sigv4.py` がやってること。

- Canonical Request をゼロから組み立てる
- credential scope 付きの String to Sign を組み立てる
- HMAC 4 段チェーン (`date -> region -> service -> aws4_request`) で Signing Key を派生
- HMAC-SHA256 で最終 Signature を計算
- `Authorization` ヘッダを組み立てる
- `https://sts.amazonaws.com/` に POST してレスポンスを表示

長期 IAM User キー (`AKIA...`) と STS 一時クレデンシャル (`ASIA...` + `X-Amz-Security-Token`) の両方に対応。

## なぜ作ったか

`boto3` のような SDK は SigV4 をメソッド 1 個の裏に隠してる。1 回手で書いてみると、実際の仕組みが見える: どのバイトに HMAC をかけるのか、credential scope に date/region/service が焼き込まれてる理由、`X-Amz-Security-Token` が通信上で何をしてるのか。

これをやった後だと、`SignatureDoesNotMatch` のデバッグが「魔法」 じゃなくなる。

## ファイル

| ファイル          | 役割                                                                                                | 外部依存 |
| ---------------- | --------------------------------------------------------------------------------------------------- | -------- |
| `sigv4.py`       | SigV4 実装本体。`STS GetCallerIdentity` を叩いて XML レスポンスを表示する                            | なし     |
| `test_sigv4.py`  | AWS 公式の `get-vanilla` SigV4 test vector に対する deterministic test。push のたびに CI で走る     | なし     |
| `get_temp.py`    | `boto3` で STS の一時クレデンシャルを取って `export ...` 行を出すヘルパー                            | `boto3`  |

主役は `sigv4.py`。`test_sigv4.py` は AWS を叩かずにアルゴリズムが正しいことを証明する。`get_temp.py` は `ASIA...` + SessionToken のパスを試すときに、一時クレデンシャルを自前で取りに行く処理を省略するためだけの補助。

## 前提

- Python 3.10 以上
- AWS アカウント
- Access Key を発行した IAM User 1 個 (Policy 添付不要、`GetCallerIdentity` はどんな IAM Identity でも無条件で動く)

## 動かす

### 長期 IAM User キーで叩く

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
python3 sigv4.py
```

期待される出力 (一部省略):

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

### STS の一時クレデンシャルで叩く

```bash
# 一時クレデンシャルを取る (内部で boto3 を使う)
pip install boto3
python3 get_temp.py

# 表示された export 行をシェルに貼り付ける
export AWS_ACCESS_KEY_ID='ASIA...'
export AWS_SECRET_ACCESS_KEY='...'
export AWS_SESSION_TOKEN='...'

# その状態で sigv4.py を叩く
python3 sigv4.py
```

`sigv4.py` は `AWS_SESSION_TOKEN` の有無を見て、自動で `X-Amz-Security-Token` ヘッダを追加して `SignedHeaders` にも含める。

レスポンスの `Arn` が `arn:aws:iam::` から `arn:aws:sts::` (assumed-role / federated) に変わるのが、「今は一時クレデンシャルで叩いてる」 ことの目印。

## コスト

`STS GetCallerIdentity` はどんな AWS アカウントでも無料で叩ける (free tier や枠の概念がない)。このスクリプトを動かしても **$0**。

## デバッグのコツ

一番よく見るのが `SignatureDoesNotMatch`。原因の頻度順:

1. **`SecretAccessKey` が間違ってる**: 環境変数を見直す
2. **時計のずれ**: ローカル時計が UTC から 15 分以上ずれてる。NTP で同期する
3. **Canonical Request の構造**: 改行が 1 個足りない / 余ってるだけで SHA256 が変わる。AWS の reference 例と byte 単位で突き合わせる
4. **ヘッダ順**: `CanonicalHeaders` はヘッダ名を小文字化してアルファベット順にソートする
5. **一時クレデンシャル使用時に `x-amz-security-token` を `SignedHeaders` に入れ忘れる**: 長期キーのコードを流用するときに見落としやすい

詰まったら `canonical_request` / `string_to_sign` / `signature` を全部 print して、AWS の公式 example と byte 単位で比較するのが一番速い。

## 対象外

- **SigV4A** (Multi-Region S3 で使う非対称版 SigV4): アルゴリズム自体が違うのでこのリポジトリの対象外
- **Presigned URL**: 署名を URL のクエリ文字列に乗せる variant。`sigv4.py` を少し直すだけで作れる
- **Streaming upload** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`): S3 の大きい PUT で使う chunk 単位の variant

どれも core は同じ。`sigv4.py` の 4 段チェーンが土台で、上の機能はその上の薄い拡張。

## ライセンス

MIT
