import { analyze } from "/lib/analyze.js";
import { parseEml } from "/lib/eml.js";
import { triageMarkdown } from "/lib/report.js";

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function table(headers, rows, classes = []) {
  const t = document.createElement("table");
  const h = document.createElement("tr");
  headers.forEach((x) => h.append(el("th", x)));
  t.append(h);
  rows.forEach((r) => { const tr = document.createElement("tr"); r.forEach((c, i) => tr.append(el("td", String(c), classes[i] ? classes[i](c) : undefined))); t.append(tr); });
  return t;
}
function cards(items) {
  const box = el("div", undefined, "cards");
  for (const [label, value, cls] of items) { const c = el("div", undefined, `card ${cls ?? ""}`); c.append(el("b", String(value)), el("span", label)); box.append(c); }
  return box;
}
function panel(title, ...kids) { const p = el("div", undefined, "panel"); p.append(el("h2", title), ...kids); return p; }
function copyButton(getMd) {
  const b = el("button", "Copy markdown");
  b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(getMd()); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy markdown"; }, 1500); } catch { /* clipboard blocked */ } });
  return b;
}
function downloadButton(getMd, name) {
  const b = el("button", "Download .md");
  b.type = "button";
  b.addEventListener("click", () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([getMd()], { type: "text/markdown" })); a.download = name; a.click(); URL.revokeObjectURL(a.href); });
  return b;
}
async function sample(name) { return (await fetch(`/examples/${name}`)).text(); }
function showError(box, e) { box.replaceChildren(el("p", String(e.message ?? e), "err")); }
function setupTabs() {
  document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll(".tab").forEach((s) => { s.hidden = s.id !== `p-${b.dataset.tab}`; });
  }));
}
const cls = (map) => (v) => map[v] ?? "";


const VCLS = { benign: "s-low", suspicious: "s-medium", "likely-phishing": "s-high", phishing: "s-high" };

function run() {
  const out = $("out");
  out.replaceChildren();
  const t = $("eml").value;
  if (!t.trim()) return;
  try {
    const a = analyze(parseEml(t));
    const md = triageMarkdown(a);
    out.append(cards([["Verdict", a.verdict, a.verdict === "benign" ? "ok" : a.verdict === "suspicious" ? "warn" : "bad"], ["Score", `${a.score}/100`], ["Links", a.links.length, a.links.some((l) => l.reasons.length) ? "warn" : "ok"], ["Attachments", a.attachments.length, a.attachments.some((x) => x.reasons.length) ? "bad" : "ok"]]));
    out.append(panel("Headers", table(["Field", "Value"], [["From", a.from ? `${a.from.name} <${a.from.email}>` : "-"], ["Reply-To", a.replyTo ? a.replyTo.email : "-"], ["Return-Path", a.returnPath ? a.returnPath.email : "-"], ["Subject", a.subject || "-"], ["SPF", a.auth.spf], ["DKIM", a.auth.dkim], ["DMARC", a.auth.dmarc]])));
    out.append(panel("Why this verdict", a.findings.length ? table(["Severity", "Finding", "Evidence"], a.findings.map((f) => [f.severity, f.title, f.evidence]), [cls({ high: "s-high", medium: "s-medium", low: "s-low", info: "s-low" })]) : el("p", "No indicators found.")));
    if (a.links.length) out.append(panel("Links (not opened)", table(["Host", "Text", "Notes"], a.links.map((l) => [l.host, l.text || "-", l.reasons.join("; ") || "-"]))));
    if (a.attachments.length) out.append(panel("Attachments", table(["Name", "Type", "Bytes", "Notes"], a.attachments.map((x) => [x.name, x.type, x.size, x.reasons.join("; ") || "-"]))));
    const row = el("div", undefined, "row");
    row.append(copyButton(() => md), downloadButton(() => md, "phish-triage.md"));
    out.append(row);
  } catch (e) { showError(out, e); }
}

for (const b of document.querySelectorAll("[data-sample]")) {
  b.addEventListener("click", async () => { $("eml").value = await sample(b.dataset.sample); run(); });
}
$("eml").addEventListener("input", run);
$("file").addEventListener("change", async (ev) => {
  const f = ev.target.files && ev.target.files[0];
  if (f) { $("eml").value = await f.text(); run(); }
});
