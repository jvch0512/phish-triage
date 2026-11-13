# phish-triage

Offline phishing e-mail triage with an explainable verdict. Feed it a raw `.eml`; it checks authentication results, sender spoofing, links, attachments and pressure language, then explains every point of the score. Zero runtime dependencies. CLI and browser tool. Nothing is fetched and no link is ever opened.

Live demo: https://jvch0512.github.io/phish-triage/ (runs in the tab, nothing is uploaded)

## Why

A SOC analyst triaging a reported e-mail repeats the same checks: do SPF, DKIM and DMARC pass and align, does Reply-To differ from From, where does each link really go, is that attachment really a PDF. phish-triage does those checks in a second and shows the evidence, so the analyst decides faster and the user gets a clear answer.

## Quick start

```bash
npm install
npm test
node dist/src/cli.js examples/phish-invoice.eml
node dist/src/cli.js examples                     # batch table over a folder
node dist/src/cli.js examples --fail-on phishing  # exit 1 for CI or mailbox pipelines
npm start                                         # UI on http://127.0.0.1:8787
```

## What it checks

| Area | Indicators |
|---|---|
| Authentication | SPF, DKIM, DMARC results from Authentication-Results or Received-SPF; DKIM and SPF domain alignment with From |
| Sender | Reply-To and Return-Path mismatch, e-mail address hidden in the display name, brand name in display name with an unrelated domain, authority claimed from a free mail provider, punycode sender |
| Links | IP hosts, user@host tricks, punycode, shorteners, brand names inside unrelated domains, visible text that shows a different domain than the real target, plain http |
| Attachments | Executable and script types, macro-enabled Office files, HTML or SVG attachments, archives, double extensions, right-to-left override, declared type versus name |
| Content | Urgency and account-threat phrases (English and Spanish), payment requests combined with secrecy (business e-mail compromise pattern) |

The BEC sample passes SPF, DKIM and DMARC (it is sent from a real free-mail account) and is still flagged, which is the point: authentication alone does not catch impersonation.

## Verdicts

Score 0 to 100 from the listed findings: benign below 20, suspicious from 20, likely-phishing from 45, phishing from 70. Fully passing authentication subtracts a little but never clears content findings.

## Limits

Heuristics, not threat intelligence. There is no reputation lookup, sandbox detonation or URL expansion, by design (offline and safe to run on a laptop). A message with stripped headers is judged on content only and says so. Treat the verdict as triage, then confirm with your mail platform and reputation tools.

## License

MIT
