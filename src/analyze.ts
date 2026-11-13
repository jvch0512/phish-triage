import { Email, Part, header, parseAddress, Address } from "./eml.js";

export type Severity = "info" | "low" | "medium" | "high";
export interface Finding { id: string; severity: Severity; title: string; evidence: string; points: number }
export type Verdict = "benign" | "suspicious" | "likely-phishing" | "phishing";

export interface Auth { spf: string; dkim: string; dmarc: string; spfDomain: string | null; dkimDomain: string | null; dmarcDomain: string | null }
export interface LinkInfo { href: string; text: string; host: string; reasons: string[] }
export interface AttachInfo { name: string; type: string; size: number; reasons: string[] }
export interface Analysis {
  from: Address | null; replyTo: Address | null; returnPath: Address | null;
  subject: string; auth: Auth; hops: string[]; links: LinkInfo[]; attachments: AttachInfo[];
  findings: Finding[]; score: number; verdict: Verdict;
}

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"]);
const RISKY_EXT = new Set(["exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "bat", "cmd", "ps1", "lnk", "iso", "img", "hta", "jar", "msi", "dll", "chm"]);
const MACRO_EXT = new Set(["docm", "xlsm", "pptm", "xlam", "dotm"]);
const ARCHIVE_EXT = new Set(["zip", "rar", "7z", "gz", "tar"]);
const HTML_EXT = new Set(["html", "htm", "shtml", "svg"]);
const DOC_EXT = new Set(["pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"]);
const URGENCY = [
  /\burgent(e|ly)?\b/i, /\bimmediately\b/i, /\binmediatamente\b/i, /\bwithin 24 hours\b/i, /\ben 24 horas\b/i,
  /\baccount (will be )?(suspended|locked|closed)\b/i, /\bsu cuenta (ser[aá] )?(suspendida|bloqueada|cancelada)\b/i,
  /\bverify your (account|identity)\b/i, /\bverifique su (cuenta|identidad)\b/i, /\bpassword (expires|expiry)\b/i,
  /\bcontrase[nñ]a (caduca|expira)\b/i, /\bunusual (sign-?in|activity)\b/i, /\bactividad inusual\b/i,
];
const PAYMENT = [/\bwire transfer\b/i, /\btransferencia\b/i, /\bgift cards?\b/i, /\btarjetas? regalo\b/i, /\bchange (of )?bank (details|account)\b/i, /\bnuevo (iban|n[uú]mero de cuenta)\b/i, /\binvoice\b/i, /\bfactura\b/i];
const SECRECY = [/\bconfidential\b/i, /\bconfidencial\b/i, /\bdo not (share|discuss)\b/i, /\bno (lo )?comentes\b/i, /\bI am (in a meeting|travelling)\b/i, /\bestoy en una reuni[oó]n\b/i];

const FREEMAIL = new Set(["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.es", "proton.me", "protonmail.com", "icloud.com", "gmx.com"]);

function authResult(v: string, method: string): { r: string; domain: string | null } {
  const m = new RegExp(`\\b${method}=(\\w+)([^;]*)`, "i").exec(v);
  if (!m) return { r: "none", domain: null };
  const d = /(?:header\.(?:d|from|i)|smtp\.mailfrom|smtp\.helo)=([^\s;]+)/i.exec(m[2] ?? "");
  const dom = d ? d[1]!.toLowerCase().replace(/^.*@/, "") : null;
  return { r: m[1]!.toLowerCase(), domain: dom };
}

export function parseAuth(e: Email): Auth {
  const all = (e.headers.get("authentication-results") ?? []).join("; ");
  const rs = (e.headers.get("received-spf") ?? [])[0] ?? "";
  const spf = authResult(all, "spf");
  if (spf.r === "none" && rs) {
    const m = /^\s*(\w+)/.exec(rs);
    if (m) spf.r = m[1]!.toLowerCase();
  }
  const dkim = authResult(all, "dkim");
  const dmarc = authResult(all, "dmarc");
  return { spf: spf.r, dkim: dkim.r, dmarc: dmarc.r, spfDomain: spf.domain, dkimDomain: dkim.domain, dmarcDomain: dmarc.domain };
}

function orgDomain(d: string): string {
  const p = d.toLowerCase().split(".");
  const twoLevel = new Set(["co.uk", "com.es", "com.br", "com.au", "org.uk", "co.jp"]);
  const last2 = p.slice(-2).join(".");
  return twoLevel.has(last2) && p.length >= 3 ? p.slice(-3).join(".") : last2;
}

function labelsLookLikeBrand(host: string): string | null {
  const brands = ["microsoft", "office365", "paypal", "amazon", "apple", "google", "netflix", "dhl", "correos", "santander", "bbva", "caixabank", "docusign", "linkedin"];
  const h = host.toLowerCase();
  const reg = orgDomain(h);
  const regLabel = reg.split(".")[0] ?? "";
  for (const b of brands) {
    if (h.includes(b) && !(regLabel === b)) return b;
  }
  return null;
}

export function extractLinks(parts: Part[]): LinkInfo[] {
  const out: LinkInfo[] = [];
  const seen = new Set<string>();
  const add = (href: string, text: string) => {
    if (seen.has(href)) return;
    seen.add(href);
    let host = "";
    const reasons: string[] = [];
    try {
      const u = new URL(href);
      if (!/^https?:$/.test(u.protocol)) return;
      host = u.hostname.toLowerCase();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[/.test(host) || /^0x[0-9a-f]+$/i.test(host)) reasons.push("IP address instead of a domain");
      if (u.username) reasons.push("credentials trick (user@host in URL)");
      if (host.includes("xn--")) reasons.push("punycode (internationalised) domain");
      if (SHORTENERS.has(host)) reasons.push("URL shortener hides the destination");
      if (u.protocol === "http:") reasons.push("unencrypted http");
      if ((host.match(/\./g) ?? []).length >= 4) reasons.push("many subdomain levels");
      const brand = labelsLookLikeBrand(host);
      if (brand) reasons.push(`brand name "${brand}" inside an unrelated domain`);
      const vt = text.trim().replace(/^https?:\/\//i, "");
      const tm = /^([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[\/?#:]|$)/i.exec(vt);
      if (tm && orgDomain(tm[1]!.toLowerCase()) !== orgDomain(host)) reasons.push(`visible text shows ${tm[1]!.toLowerCase()} but link goes to ${host}`);
      if (/\.(zip|mov)$/i.test(host)) reasons.push("TLD that doubles as a file extension");
    } catch { return; }
    out.push({ href, text: text.trim().slice(0, 80), host, reasons });
  };
  for (const p of [...parts].sort((a, b) => Number(b.contentType === "text/html") - Number(a.contentType === "text/html"))) {
    if (p.contentType === "text/html") {
      const re = /<a\b[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*>([\s\S]*?)<\/a>/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(p.text))) add(decodeEntities(m[1] ?? m[2] ?? ""), decodeEntities(m[3]!.replace(/<[^>]+>/g, "")));
    } else if (p.contentType === "text/plain") {
      for (const m of p.text.matchAll(/https?:\/\/[^\s<>"')]+/gi)) add(m[0].replace(/[.,;]+$/, ""), "");
    }
  }
  return out;
}

function decodeEntities(s: string): string {
  return s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#(\d+);/g, (_m, n: string) => String.fromCharCode(Number(n)));
}

export function attachmentInfo(parts: Part[]): AttachInfo[] {
  const out: AttachInfo[] = [];
  for (const p of parts) {
    const isAtt = p.filename || p.disposition === "attachment";
    if (!isAtt) continue;
    const name = p.filename ?? "(unnamed)";
    const exts = name.toLowerCase().split(".").slice(1);
    const ext = exts[exts.length - 1] ?? "";
    const reasons: string[] = [];
    if (RISKY_EXT.has(ext)) reasons.push(`executable or script type .${ext}`);
    if (MACRO_EXT.has(ext)) reasons.push(`macro-enabled Office file .${ext}`);
    if (HTML_EXT.has(ext)) reasons.push("HTML or SVG attachment (credential-harvesting pattern)");
    if (ARCHIVE_EXT.has(ext)) reasons.push("archive can hide its content from scanners");
    if (exts.length >= 2 && DOC_EXT.has(exts[exts.length - 2]!) && (RISKY_EXT.has(ext) || HTML_EXT.has(ext) || MACRO_EXT.has(ext))) reasons.push("double extension disguises the real type");
    if (/[‮]/.test(name)) reasons.push("right-to-left override character in the file name");
    if (ext === "pdf" && p.contentType !== "application/pdf" && p.contentType !== "application/octet-stream") reasons.push(`declared ${p.contentType} but named .pdf`);
    out.push({ name, type: p.contentType, size: p.size, reasons });
  }
  return out;
}

export function analyze(e: Email): Analysis {
  const findings: Finding[] = [];
  const f = (id: string, severity: Severity, title: string, evidence: string, points: number) => findings.push({ id, severity, title, evidence, points });
  const from = parseAddress(header(e, "from"));
  const replyTo = parseAddress(header(e, "reply-to"));
  const returnPath = parseAddress(header(e, "return-path"));
  const subject = header(e, "subject") ?? "";
  const auth = parseAuth(e);
  const hops = (e.headers.get("received") ?? []).map((r) => r.replace(/\s+/g, " ").slice(0, 160));

  if (!from) f("no-from", "high", "No parsable From address", header(e, "from") ?? "(missing)", 20);
  if (auth.spf === "fail" || auth.spf === "softfail") f("spf-fail", "high", "SPF did not pass", `spf=${auth.spf}${auth.spfDomain ? ` for ${auth.spfDomain}` : ""}`, auth.spf === "fail" ? 25 : 15);
  if (auth.dkim === "fail") f("dkim-fail", "high", "DKIM signature failed", `dkim=${auth.dkim}${auth.dkimDomain ? ` d=${auth.dkimDomain}` : ""}`, 20);
  if (auth.dmarc === "fail") f("dmarc-fail", "high", "DMARC failed", `dmarc=${auth.dmarc}${auth.dmarcDomain ? ` from ${auth.dmarcDomain}` : ""}`, 25);
  if (auth.spf === "none" && auth.dkim === "none" && auth.dmarc === "none") f("no-auth", "medium", "No authentication results present", "No Authentication-Results or Received-SPF header; verdict relies on content only (headers may have been stripped by a forwarder or a copy-paste).", 8);
  if (from && auth.dkim === "pass" && auth.dkimDomain && orgDomain(auth.dkimDomain) !== orgDomain(from.domain)) f("dkim-misaligned", "medium", "DKIM passes for a different domain than From", `d=${auth.dkimDomain} but From is ${from.domain}`, 10);
  if (from && auth.spf === "pass" && auth.spfDomain && orgDomain(auth.spfDomain) !== orgDomain(from.domain) && auth.dmarc !== "pass") f("spf-misaligned", "medium", "SPF passes for a different domain than From", `${auth.spfDomain} vs ${from.domain}`, 10);
  if (from && replyTo && orgDomain(from.domain) !== orgDomain(replyTo.domain)) f("replyto-mismatch", "high", "Reply-To points to a different domain", `From ${from.email}, Reply-To ${replyTo.email}`, 20);
  if (from && returnPath && orgDomain(from.domain) !== orgDomain(returnPath.domain) && auth.dmarc !== "pass") f("returnpath-mismatch", "low", "Return-Path domain differs from From", `${returnPath.domain} vs ${from.domain}`, 5);
  if (from && from.name) {
    const em = /[\w.+-]+@[\w-]+(\.[\w-]+)+/.exec(from.name);
    if (em && orgDomain(em[0].split("@")[1]!) !== orgDomain(from.domain)) f("display-spoof", "high", "Display name contains a different e-mail address", `"${from.name}" <${from.email}>`, 20);
    const brand = labelsLookLikeBrand(from.name.replace(/\s+/g, ""));
    if (brand && orgDomain(from.domain).split(".")[0] !== brand) f("brand-impersonation", "high", "Display name uses a brand the sender domain does not belong to", `"${from.name}" <${from.email}>`, 20);
    if (FREEMAIL.has(from.domain) && /\b(ceo|cfo|director|presidente|gerente|finance|finanzas|hr|rrhh|soporte|support|security|seguridad)\b/i.test(from.name)) f("freemail-exec", "medium", "Role or authority claimed from a free mail provider", `"${from.name}" <${from.email}>`, 12);
  }
  if (from && from.domain.includes("xn--")) f("punycode-from", "high", "Sender domain is punycode", from.domain, 15);
  if (hops.length === 0) f("no-received", "low", "No Received headers", "Message may have been re-created or exported without transport headers.", 4);

  const body = e.parts.filter((p) => p.contentType.startsWith("text/")).map((p) => p.text.replace(/<[^>]+>/g, " ")).join("\n");
  const subj = `${subject}\n${body}`;
  const urg = URGENCY.filter((r) => r.test(subj)).length;
  if (urg) f("urgency", urg >= 2 ? "medium" : "low", "Urgency or account-threat language", `${urg} pressure phrase${urg > 1 ? "s" : ""} matched`, Math.min(15, 6 * urg));
  const pay = PAYMENT.filter((r) => r.test(subj)).length;
  const sec = SECRECY.filter((r) => r.test(subj)).length;
  if (pay && sec) f("bec-pattern", "high", "Payment request combined with secrecy or unavailability", "Typical business e-mail compromise wording", 35);
  else if (pay >= 2 && /(iban|bank|banco|cuenta)/i.test(subj)) f("payment-detail", "medium", "Payment or bank-detail request", "Verify out of band before acting", 10);

  const links = extractLinks(e.parts);
  const badLinks = links.filter((l) => l.reasons.length);
  for (const l of badLinks.slice(0, 5)) f("link", l.reasons.some((r) => /text shows|credentials|IP address|brand/.test(r)) ? "high" : "medium", "Suspicious link", `${l.host}: ${l.reasons.join("; ")}`, l.reasons.some((r) => /text shows|credentials|IP address|brand/.test(r)) ? 20 : 10);

  const atts = attachmentInfo(e.parts);
  for (const a of atts) if (a.reasons.length) f("attachment", a.reasons.some((r) => /executable|macro|double|override/.test(r)) ? "high" : "medium", "Risky attachment", `${a.name}: ${a.reasons.join("; ")}`, a.reasons.some((r) => /executable|macro|double|override/.test(r)) ? 25 : 12);

  const strong = auth.dmarc === "pass" && auth.spf === "pass" && auth.dkim === "pass";
  let score = findings.reduce((n, x) => n + x.points, 0);
  if (strong && score > 0) { score = Math.max(0, score - 10); f("auth-clean", "info", "SPF, DKIM and DMARC all pass", "Authentication passes; this reduces but does not remove risk (compromised or look-alike senders can authenticate).", -10); }
  score = Math.min(100, score);
  const verdict: Verdict = score >= 70 ? "phishing" : score >= 45 ? "likely-phishing" : score >= 20 ? "suspicious" : "benign";
  findings.sort((a, b) => ["high", "medium", "low", "info"].indexOf(a.severity) - ["high", "medium", "low", "info"].indexOf(b.severity));
  return { from, replyTo, returnPath, subject, auth, hops, links, attachments: atts, findings, score, verdict };
}
