import { Analysis } from "./analyze.js";

const ICON: Record<string, string> = { high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };

export function triageMarkdown(a: Analysis): string {
  const L: string[] = [];
  L.push("# Phishing triage", "");
  L.push(`Verdict: **${a.verdict}** (score ${a.score}/100)`, "");
  L.push(`| Field | Value |`, `|---|---|`);
  L.push(`| From | ${a.from ? `${a.from.name ? a.from.name + " " : ""}<${a.from.email}>` : "-"} |`);
  L.push(`| Reply-To | ${a.replyTo?.email ?? "-"} |`, `| Return-Path | ${a.returnPath?.email ?? "-"} |`, `| Subject | ${a.subject || "-"} |`);
  L.push(`| SPF / DKIM / DMARC | ${a.auth.spf} / ${a.auth.dkim} / ${a.auth.dmarc} |`, "");
  L.push("## Why", "");
  if (!a.findings.length) L.push("No indicators found.");
  for (const f of a.findings) L.push(`- **${ICON[f.severity]}** ${f.title}: ${f.evidence}`);
  if (a.links.length) {
    L.push("", "## Links", "", "| Host | Text | Notes |", "|---|---|---|");
    for (const l of a.links) L.push(`| ${l.host} | ${l.text.replace(/\|/g, "/") || "-"} | ${l.reasons.join("; ") || "-"} |`);
  }
  if (a.attachments.length) {
    L.push("", "## Attachments", "", "| Name | Type | Bytes | Notes |", "|---|---|---|---|");
    for (const t of a.attachments) L.push(`| ${t.name} | ${t.type} | ${t.size} | ${t.reasons.join("; ") || "-"} |`);
  }
  if (a.hops.length) {
    L.push("", "## Received chain (newest first)", "");
    a.hops.forEach((h, i) => L.push(`${i + 1}. ${h}`));
  }
  L.push("", "## Suggested response", "");
  if (a.verdict === "benign") L.push("No action beyond normal hygiene. If the user still doubts it, verify through a separate channel.");
  else {
    L.push("1. Do not click links or open attachments; keep the original .eml as evidence.");
    L.push("2. Search the mailbox platform for the same sender, subject and link host, and quarantine matches.");
    L.push("3. Block the sender domain and the link hosts; submit the URLs and hashes to your reputation service.");
    L.push("4. If anyone clicked or opened it, reset credentials, revoke sessions and review sign-in logs.");
    if (a.findings.some((f) => f.id === "bec-pattern" || f.id === "payment-detail")) L.push("5. For payment requests, call the requester on a known number before any transfer.");
  }
  L.push("", "Heuristic triage, not a replacement for sandbox or reputation lookups. Nothing was fetched from the network.");
  return L.join("\n") + "\n";
}
