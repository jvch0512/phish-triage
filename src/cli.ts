#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { analyze, Verdict } from "./analyze.js";
import { EmlError, parseEml } from "./eml.js";
import { triageMarkdown } from "./report.js";

const USAGE = `phish-triage

  phish-triage <file.eml|dir> [--json] [--fail-on suspicious|likely-phishing|phishing]

Offline: nothing is fetched. Exit codes: 0 ok, 1 verdict at or above --fail-on, 2 bad input.`;

const ORDER: Verdict[] = ["benign", "suspicious", "likely-phishing", "phishing"];

function files(p: string): string[] {
  return statSync(p).isDirectory() ? readdirSync(p).filter((f) => f.endsWith(".eml")).sort().map((f) => join(p, f)) : [p];
}

function main(argv: string[]): number {
  const target = argv.find((a) => !a.startsWith("--") && argv[argv.indexOf(a) - 1] !== "--fail-on");
  if (!target) { console.error(USAGE); return 2; }
  const json = argv.includes("--json");
  const fi = argv.indexOf("--fail-on");
  const failOn = fi >= 0 ? argv[fi + 1] as Verdict : undefined;
  if (failOn && !ORDER.includes(failOn)) { console.error(`--fail-on must be one of ${ORDER.slice(1).join(", ")}`); return 2; }
  try {
    let worst = 0;
    const results = files(target).map((f) => ({ f, a: analyze(parseEml(readFileSync(f, "utf8"))) }));
    for (const { f, a } of results) worst = Math.max(worst, ORDER.indexOf(a.verdict));
    if (json) process.stdout.write(JSON.stringify(results.map(({ f, a }) => ({ file: f, ...a })), null, 2) + "\n");
    else if (results.length === 1) process.stdout.write(triageMarkdown(results[0]!.a));
    else {
      process.stdout.write("# Phishing triage batch\n\n| File | Verdict | Score | Top finding |\n|---|---|---|---|\n");
      for (const { f, a } of results) process.stdout.write(`| ${f} | ${a.verdict} | ${a.score} | ${a.findings[0]?.title ?? "-"} |\n`);
    }
    return failOn && worst >= ORDER.indexOf(failOn) ? 1 : 0;
  } catch (e) {
    if (e instanceof EmlError || (e as NodeJS.ErrnoException).code === "ENOENT") { console.error(`error: ${(e as Error).message}`); return 2; }
    throw e;
  }
}

process.exitCode = main(process.argv.slice(2));
