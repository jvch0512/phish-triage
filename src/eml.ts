export interface Part {
  headers: Map<string, string[]>;
  contentType: string;
  filename: string | null;
  disposition: string;
  text: string;
  size: number;
}

export interface Email {
  headers: Map<string, string[]>;
  raw: string[][];
  parts: Part[];
}

export class EmlError extends Error {}

export function decodeWords(s: string): string {
  return s
    .replace(/\?=\s+=\?/g, "?==?")
    .replace(/=\?([\w-]+)\?([bBqQ])\?([^?]*)\?=/g, (_m, cs: string, enc: string, body: string) => {
      try {
        const bytes = enc.toLowerCase() === "b"
          ? fromB64(body)
          : latin1Bytes(body.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_x, h: string) => String.fromCharCode(parseInt(h, 16))));
        return new TextDecoder(cs.toLowerCase() === "utf-8" ? "utf-8" : cs).decode(bytes);
      } catch { return body; }
    });
}

function splitHeadBody(text: string): [string, string] {
  const m = /\r?\n\r?\n/.exec(text);
  return m ? [text.slice(0, m.index), text.slice(m.index + m[0].length)] : [text, ""];
}

export function parseHeaders(block: string): { map: Map<string, string[]>; raw: string[][] } {
  const map = new Map<string, string[]>();
  const raw: string[][] = [];
  const lines = block.split(/\r?\n/);
  const folded: string[] = [];
  for (const l of lines) {
    if (/^[ \t]/.test(l) && folded.length) folded[folded.length - 1] += " " + l.trim();
    else folded.push(l);
  }
  for (const l of folded) {
    const i = l.indexOf(":");
    if (i <= 0) continue;
    const k = l.slice(0, i).trim().toLowerCase();
    const v = l.slice(i + 1).trim();
    raw.push([k, v]);
    map.set(k, [...(map.get(k) ?? []), v]);
  }
  return { map, raw };
}

export function param(value: string, name: string): string | null {
  const re = new RegExp(`${name}\\*?=\\s*(?:"([^"]*)"|([^;\\s]+))`, "i");
  const m = re.exec(value);
  return m ? (m[1] ?? m[2] ?? null) : null;
}

function latin1Bytes(s: string): Uint8Array {
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 255;
  return b;
}

function fromB64(s: string): Uint8Array {
  return latin1Bytes(atob(s.replace(/\s+/g, "")));
}

function decodeBody(body: string, cte: string, charset: string): string {
  const e = cte.toLowerCase().trim();
  let bytes: Uint8Array;
  if (e === "base64") bytes = fromB64(body);
  else if (e === "quoted-printable") {
    const s = body.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
    bytes = latin1Bytes(s);
  } else bytes = new TextEncoder().encode(body);
  try { return new TextDecoder(charset || "utf-8").decode(bytes); } catch { return new TextDecoder().decode(bytes); }
}

function walk(text: string, out: Part[], depth: number): { map: Map<string, string[]>; raw: string[][] } {
  const [head, body] = splitHeadBody(text);
  const h = parseHeaders(head);
  const ct = h.map.get("content-type")?.[0] ?? "text/plain";
  const type = ct.split(";")[0]!.trim().toLowerCase();
  if (type.startsWith("multipart/") && depth < 8) {
    const b = param(ct, "boundary");
    if (b) {
      const pieces = body.split(new RegExp(`\\r?\\n?--${b.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:--)?[ \\t]*\\r?\\n?`));
      for (const p of pieces.slice(1)) if (p.trim()) walk(p.replace(/^\r?\n/, ""), out, depth + 1);
      return h;
    }
  }
  const disp = h.map.get("content-disposition")?.[0] ?? "";
  const fname = param(disp, "filename") ?? param(ct, "name");
  const cte = h.map.get("content-transfer-encoding")?.[0] ?? "7bit";
  const isText = type.startsWith("text/") || type === "message/rfc822";
  out.push({
    headers: h.map,
    contentType: type,
    filename: fname ? decodeWords(fname) : null,
    disposition: disp.split(";")[0]!.trim().toLowerCase(),
    text: isText ? decodeBody(body, cte, param(ct, "charset") ?? "utf-8") : "",
    size: cte.toLowerCase().includes("base64") ? Math.floor(body.replace(/\s+/g, "").length * 0.75) : body.length,
  });
  return h;
}

export function parseEml(src: string): Email {
  if (!src.trim()) throw new EmlError("empty input");
  const parts: Part[] = [];
  const t = src.replace(/^﻿/, "").replace(/^From .*\r?\n/, "");
  const top = walk(t, parts, 0);
  if (!top.map.has("from") && !top.map.has("received")) throw new EmlError("no e-mail headers found (expected From: or Received:)");
  return { headers: top.map, raw: top.raw, parts };
}

export function header(e: Email, name: string): string | undefined {
  const v = e.headers.get(name.toLowerCase())?.[0];
  return v === undefined ? undefined : decodeWords(v);
}

export interface Address { name: string; email: string; domain: string }

export function parseAddress(v: string | undefined): Address | null {
  if (!v) return null;
  const s = decodeWords(v);
  const m = /^\s*"?([^"<]*?)"?\s*<([^>]+)>/.exec(s);
  const email = (m ? m[2]! : s).trim().replace(/^mailto:/i, "").toLowerCase();
  const at = email.lastIndexOf("@");
  if (at < 1) return null;
  return { name: m ? m[1]!.trim() : "", email, domain: email.slice(at + 1).replace(/[>\s].*$/, "") };
}
