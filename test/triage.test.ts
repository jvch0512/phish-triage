import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyze, extractLinks, attachmentInfo, parseAuth } from "../src/analyze.js";
import { decodeWords, parseAddress, parseEml, EmlError } from "../src/eml.js";
import { triageMarkdown } from "../src/report.js";

const ex = (n: string) => analyze(parseEml(readFileSync(`examples/${n}`, "utf8")));

test("decodeWords handles B and Q encodings", () => {
  assert.equal(decodeWords("=?UTF-8?B?SG9sYSDDsQ==?="), "Hola ñ");
  assert.equal(decodeWords("=?UTF-8?Q?Se=C3=B1or_Garc=C3=ADa?="), "Señor García");
});

test("parseAddress extracts name, email and domain", () => {
  assert.deepEqual(parseAddress('"A B" <A.B@Example.COM>'), { name: "A B", email: "a.b@example.com", domain: "example.com" });
  assert.equal(parseAddress("nonsense"), null);
});

test("rejects input without e-mail headers", () => {
  assert.throws(() => parseEml("hello world"), EmlError);
  assert.throws(() => parseEml(""), EmlError);
});

test("parses multipart and decodes base64 attachment name and size", () => {
  const e = parseEml(readFileSync("examples/phish-invoice.eml", "utf8"));
  assert.equal(e.parts.length, 2);
  assert.equal(e.parts[1]!.filename, "Factura_88231.pdf.html");
});

test("auth results parsed", () => {
  const a = parseAuth(parseEml(readFileSync("examples/phish-invoice.eml", "utf8")));
  assert.equal(a.spf, "fail"); assert.equal(a.dkim, "none"); assert.equal(a.dmarc, "fail");
  assert.equal(a.spfDomain, "billing-dhl-express.test");
});

test("phishing sample is flagged with the expected findings", () => {
  const r = ex("phish-invoice.eml");
  assert.equal(r.verdict, "phishing");
  const ids = r.findings.map((f) => f.id);
  for (const id of ["spf-fail", "dmarc-fail", "replyto-mismatch", "brand-impersonation", "urgency", "link", "attachment"]) assert.ok(ids.includes(id), id);
  assert.equal(r.subject.startsWith("Urgente: factura"), true);
});

test("BEC sample is caught even though SPF, DKIM and DMARC pass", () => {
  const r = ex("bec-ceo.eml");
  assert.notEqual(r.verdict, "benign");
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes("bec-pattern")); assert.ok(ids.includes("freemail-exec"));
});

test("legitimate newsletter is benign", () => {
  const r = ex("legit-newsletter.eml");
  assert.equal(r.verdict, "benign"); assert.equal(r.score, 0); assert.equal(r.links.length, 1);
});

test("link heuristics", () => {
  const mk = (h: string, t = "") => extractLinks([{ headers: new Map(), contentType: "text/html", filename: null, disposition: "", text: `<a href="${h}">${t}</a>`, size: 0 }])[0]!;
  assert.ok(mk("http://192.0.2.1/x").reasons.some((r) => r.includes("IP")));
  assert.ok(mk("https://user@evil.test/").reasons.some((r) => r.includes("credentials")));
  assert.ok(mk("https://xn--pypal-4ve.test/").reasons.some((r) => r.includes("punycode")));
  assert.ok(mk("https://evil.test/", "www.bank.example/login").reasons.some((r) => r.includes("visible text")));
  assert.ok(mk("https://login.microsoft.evil-host.test/").reasons.some((r) => r.includes("brand")));
  assert.equal(mk("https://www.vendor.example/a", "vendor.example/a").reasons.length, 0);
});

test("attachment heuristics", () => {
  const p = (filename: string, contentType = "application/octet-stream") => ({ headers: new Map(), contentType, filename, disposition: "attachment", text: "", size: 10 });
  assert.ok(attachmentInfo([p("invoice.pdf.exe")])[0]!.reasons.some((r) => r.includes("double")));
  assert.ok(attachmentInfo([p("budget.xlsm")])[0]!.reasons.some((r) => r.includes("macro")));
  assert.equal(attachmentInfo([p("report.pdf", "application/pdf")])[0]!.reasons.length, 0);
});

test("missing authentication headers are noted, not treated as a failure", () => {
  const r = analyze(parseEml("From: a@b.example\nSubject: hi\n\nhello"));
  assert.ok(r.findings.some((f) => f.id === "no-auth"));
  assert.equal(r.verdict, "benign");
});

test("report renders verdict and suggested response", () => {
  const md = triageMarkdown(ex("phish-invoice.eml"));
  assert.match(md, /Verdict: \*\*phishing\*\*/);
  assert.match(md, /Suggested response/);
});
