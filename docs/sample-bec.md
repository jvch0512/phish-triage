# Phishing triage

Verdict: **likely-phishing** (score 49/100)

| Field | Value |
|---|---|
| From | Carlos Mendez CEO <carlos.mendez.ceo@gmail.com> |
| Reply-To | - |
| Return-Path | - |
| Subject | Transferencia urgente confidencial |
| SPF / DKIM / DMARC | pass / pass / pass |

## Why

- **HIGH** Payment request combined with secrecy or unavailability: Typical business e-mail compromise wording
- **MED** Role or authority claimed from a free mail provider: "Carlos Mendez CEO" <carlos.mendez.ceo@gmail.com>
- **MED** Urgency or account-threat language: 2 pressure phrases matched
- **INFO** SPF, DKIM and DMARC all pass: Authentication passes; this reduces but does not remove risk (compromised or look-alike senders can authenticate).

## Received chain (newest first)

1. from smtp.freemail.example (smtp.freemail.example [192.0.2.80]) by mx.acme-corp.example with ESMTPS; Tue, 03 Nov 2026 17:02:11 +0100

## Suggested response

1. Do not click links or open attachments; keep the original .eml as evidence.
2. Search the mailbox platform for the same sender, subject and link host, and quarantine matches.
3. Block the sender domain and the link hosts; submit the URLs and hashes to your reputation service.
4. If anyone clicked or opened it, reset credentials, revoke sessions and review sign-in logs.
5. For payment requests, call the requester on a known number before any transfer.

Heuristic triage, not a replacement for sandbox or reputation lookups. Nothing was fetched from the network.
