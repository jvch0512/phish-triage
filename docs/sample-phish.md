# Phishing triage

Verdict: **phishing** (score 100/100)

| Field | Value |
|---|---|
| From | DHL Express Billing <invoices@billing-dhl-express.test> |
| Reply-To | collections.desk@proton.me |
| Return-Path | bounce@billing-dhl-express.test |
| Subject | Urgente: factura pendiente, su cuenta será suspendida |
| SPF / DKIM / DMARC | fail / none / fail |

## Why

- **HIGH** SPF did not pass: spf=fail for billing-dhl-express.test
- **HIGH** DMARC failed: dmarc=fail from dhl.example
- **HIGH** Reply-To points to a different domain: From invoices@billing-dhl-express.test, Reply-To collections.desk@proton.me
- **HIGH** Display name uses a brand the sender domain does not belong to: "DHL Express Billing" <invoices@billing-dhl-express.test>
- **HIGH** Suspicious link: 198.51.100.20: IP address instead of a domain; unencrypted http; visible text shows www.dhl.example but link goes to 198.51.100.20
- **HIGH** Risky attachment: Factura_88231.pdf.html: HTML or SVG attachment (credential-harvesting pattern); double extension disguises the real type
- **MED** Urgency or account-threat language: 5 pressure phrases matched
- **MED** Suspicious link: bit.ly: URL shortener hides the destination

## Links

| Host | Text | Notes |
|---|---|---|
| 198.51.100.20 | https://www.dhl.example/mi-factura | IP address instead of a domain; unencrypted http; visible text shows www.dhl.example but link goes to 198.51.100.20 |
| bit.ly | Descargar factura | URL shortener hides the destination |

## Attachments

| Name | Type | Bytes | Notes |
|---|---|---|---|
| Factura_88231.pdf.html | application/octet-stream | 54 | HTML or SVG attachment (credential-harvesting pattern); double extension disguises the real type |

## Received chain (newest first)

1. from mail-gw.mailer-pool.test (mail-gw.mailer-pool.test [203.0.113.45]) by mx.acme-corp.example with ESMTP; Mon, 02 Nov 2026 08:14:22 +0100
2. from localhost (unknown [198.51.100.7]) by mail-gw.mailer-pool.test; Mon, 02 Nov 2026 08:14:20 +0100

## Suggested response

1. Do not click links or open attachments; keep the original .eml as evidence.
2. Search the mailbox platform for the same sender, subject and link host, and quarantine matches.
3. Block the sender domain and the link hosts; submit the URLs and hashes to your reputation service.
4. If anyone clicked or opened it, reset credentials, revoke sessions and review sign-in logs.

Heuristic triage, not a replacement for sandbox or reputation lookups. Nothing was fetched from the network.
