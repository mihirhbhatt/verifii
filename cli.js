#!/usr/bin/env node
import { lstat, readFile, readdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { dirname, extname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { formatSize, scanBuffer } from "./scanner.js";
import { createNistAlignment, THREAT_CATALOG } from "./threat-catalog.js";

const MAX_FILE_SIZE = 25 * 1024 * 1024;
const PROJECT_ROOT = dirname(fileURLToPath(import.meta.url));
const IGNORED_DIRECTORIES = new Set([
  ".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build"
]);
const SEVERITY_LEVEL = { critical: 4, high: 3, medium: 2, low: 1 };

export function parseArgs(args) {
  const options = { format: "text", failOn: "high" };
  let remaining = args;
  if (remaining[0] === "test" || (remaining[0] === "cli" && remaining[1] === "--test")) {
    if (remaining.length !== (remaining[0] === "test" ? 1 : 2)) {
      throw new Error("Use `verifii test` without additional arguments.");
    }
    return { command: "test", help: false };
  }
  if (remaining[0] === "threat") {
    if (remaining.length === 2 && remaining[1] === "status") {
      return { command: "threat-status", help: false };
    }
    throw new Error("Use `verifii threat status`.");
  }
  if (remaining[0] === "cli") {
    if (remaining[1] === "--help" || remaining[1] === "-h") return { help: true };
    if (remaining[1] !== "--scan") throw new Error("Use `verifii cli --scan [file-or-directory]`.");
    remaining = remaining.slice(2);
  } else if (remaining[0] === "--scan") {
    remaining = remaining.slice(1);
  } else if (remaining[0] === "scan") {
    remaining = remaining.slice(1);
  } else if (remaining[0] !== "--help" && remaining[0] !== "-h") {
    throw new Error("Use `verifii cli --scan [file-or-directory]`.");
  }
  const positionals = [];
  for (let index = 0; index < remaining.length; index++) {
    const argument = remaining[index];
    if (argument === "--help" || argument === "-h") {
      return { help: true };
    }
    if (argument === "--format") {
      const value = remaining[++index];
      if (!["text", "json"].includes(value)) throw new Error("--format must be either text or json.");
      options.format = value;
      continue;
    }
    if (argument === "--fail-on") {
      const value = remaining[++index];
      if (!["critical", "high", "medium", "low", "never"].includes(value)) {
        throw new Error("--fail-on must be critical, high, medium, low, or never.");
      }
      options.failOn = value;
      continue;
    }
    if (argument === "--framework") {
      const value = remaining[++index];
      if (value !== "nist-ai-rmf") throw new Error("--framework currently supports nist-ai-rmf.");
      options.framework = value;
      continue;
    }
    if (argument.startsWith("-")) throw new Error(`Unknown option: ${argument}`);
    positionals.push(argument);
  }
  if (positionals.length > 1) throw new Error("Provide no more than one file or directory to scan.");
  return { ...options, command: "scan", target: positionals[0] || ".", help: false };
}

async function listFiles(target) {
  const info = await lstat(target);
  if (info.isSymbolicLink()) {
    throw new Error(`Refusing to follow symbolic link: ${target}`);
  }
  if (info.isFile()) return [target];
  if (!info.isDirectory()) throw new Error(`Not a regular file or directory: ${target}`);

  const entries = await readdir(target, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name));
  const files = [];
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory() && IGNORED_DIRECTORIES.has(entry.name)) continue;
    const child = resolve(target, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listFiles(child));
    } else if (entry.isFile()) {
      files.push(child);
    }
  }
  return files;
}

function arrayBufferFrom(buffer) {
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

export async function scanPath(path) {
  const target = resolve(path);
  const root = (await lstat(target)).isDirectory() ? target : resolve(target, "..");
  const paths = await listFiles(target);
  const artifacts = [];
  const errors = [];
  for (const filePath of paths) {
    const name = relative(root, filePath).split(sep).join("/");
    try {
      const info = await lstat(filePath);
      if (info.size > MAX_FILE_SIZE || extname(name).toLowerCase() === ".pdf") {
        artifacts.push(scanBuffer(name, info.size, new ArrayBuffer(0)));
        continue;
      }
      const buffer = await readFile(filePath);
      artifacts.push(scanBuffer(name, info.size, arrayBufferFrom(buffer)));
    } catch (error) {
      errors.push({ path: name, message: error.message });
    }
  }
  return { target, artifacts, errors, scannedAt: new Date().toISOString() };
}

export function exitCodeForReport(report, failOn) {
  if (report.errors.length > 0) return 2;
  if (failOn === "never") return 0;
  const threshold = SEVERITY_LEVEL[failOn];
  return report.artifacts.some((artifact) =>
    artifact.findings.some((finding) => SEVERITY_LEVEL[finding.severity] >= threshold)
  ) ? 1 : 0;
}

function renderText(report) {
  const lines = [
    `Verifii scan — ${report.target}`,
    `Threat definitions: ${report.threatCatalog.version} (updated ${report.threatCatalog.updatedAt}; ${report.threatCatalog.updateMode})`,
    ""
  ];
  for (const artifact of report.artifacts) {
    lines.push(`${artifact.status.toUpperCase().padEnd(11)} ${artifact.name} (${formatSize(artifact.size)})`);
    if (artifact.note) lines.push(`  Note: ${artifact.note}`);
    for (const finding of artifact.findings) {
      const location = finding.line ? `:${finding.line}` : "";
      lines.push(`  [${finding.severity.toUpperCase()}] ${finding.title}${location}`);
      lines.push(`    ${finding.description}`);
      if (finding.threatDefinition?.nistFunctions?.length) {
        lines.push(`    NIST AI RMF functions (informative): ${finding.threatDefinition.nistFunctions.join(", ")}`);
      }
      if (finding.snippet) lines.push(`    > ${finding.snippet}`);
    }
  }
  for (const error of report.errors) {
    lines.push(`ERROR       ${error.path}: ${error.message}`);
  }
  const totals = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const artifact of report.artifacts) {
    for (const finding of artifact.findings) totals[finding.severity]++;
  }
  lines.push("");
  lines.push(`Scanned ${report.artifacts.length} file(s): ${totals.critical} critical, ${totals.high} high, ${totals.medium} medium, ${totals.low} low; ${report.errors.length} error(s).`);
  if (report.frameworkAlignment) {
    lines.push("");
    lines.push(`${report.frameworkAlignment.framework.name} ${report.frameworkAlignment.framework.version} — informative scanner evidence`);
    for (const frameworkFunction of report.frameworkAlignment.framework.functions) {
      lines.push(`  ${frameworkFunction.id}: ${report.frameworkAlignment.evidenceCountsByFunction[frameworkFunction.id]} mapped finding(s)`);
    }
    lines.push(`  Not assessed: ${report.frameworkAlignment.notAssessed.length} organizational/system-level areas.`);
    lines.push(`  ${report.frameworkAlignment.disclaimer}`);
  }
  lines.push("Heuristic results only — a clean scan is not proof that an artifact is safe.");
  return lines.join("\n");
}

function renderThreatStatus() {
  const sources = THREAT_CATALOG.sources.map((source) => `  ${source.name}: ${source.url}`);
  return [
    "Verifii threat-definition status",
    `  Catalog: ${THREAT_CATALOG.id}`,
    `  Version: ${THREAT_CATALOG.version}`,
    `  Updated: ${THREAT_CATALOG.updatedAt}`,
    `  Definitions: ${THREAT_CATALOG.definitions.length}`,
    `  Update mode: ${THREAT_CATALOG.updateMode}`,
    `  ${THREAT_CATALOG.summary}`,
    "  Sources:",
    ...sources,
    ""
  ].join("\n");
}

function runTests() {
  return new Promise((resolveExit, reject) => {
    const child = spawn(process.execPath, ["--test"], {
      cwd: PROJECT_ROOT,
      stdio: "inherit",
      shell: false,
      windowsHide: true
    });
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code !== null) {
        resolveExit(code);
      } else {
        reject(new Error(`Test runner terminated${signal ? ` by ${signal}` : ""}.`));
      }
    });
  });
}

export async function main(args, io = { stdout: process.stdout, stderr: process.stderr }) {
  let options;
  try {
    options = parseArgs(args);
  } catch (error) {
    io.stderr.write(`verifii: ${error.message}\n\n${usage()}`);
    return 2;
  }
  if (options.help) {
    io.stdout.write(usage());
    return 0;
  }
  if (options.command === "threat-status") {
    io.stdout.write(renderThreatStatus());
    return 0;
  }
  if (options.command === "test") {
    try {
      return await runTests();
    } catch (error) {
      io.stderr.write(`verifii: unable to run tests: ${error.message}\n`);
      return 2;
    }
  }
  let report;
  try {
    report = await scanPath(options.target);
  } catch (error) {
    io.stderr.write(`verifii: ${error.message}\n`);
    return 2;
  }
  report.threatCatalog = {
    id: THREAT_CATALOG.id,
    version: THREAT_CATALOG.version,
    updatedAt: THREAT_CATALOG.updatedAt,
    updateMode: THREAT_CATALOG.updateMode,
    sources: THREAT_CATALOG.sources
  };
  if (options.framework === "nist-ai-rmf") {
    report.frameworkAlignment = createNistAlignment(report.artifacts);
  }
  if (options.format === "json") {
    io.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    io.stdout.write(`${renderText(report)}\n`);
  }
  return exitCodeForReport(report, options.failOn);
}

function usage() {
  return [
    "Verifii — local-first AI artifact security scanner",
    "",
    "Usage:",
    "  verifii cli --scan [file-or-directory] [--format text|json] [--fail-on critical|high|medium|low|never] [--framework nist-ai-rmf]",
    "  verifii scan <file-or-directory> [options]  (short alias)",
    "  verifii test",
    "  verifii threat status",
    "",
    "Options:",
    "  --format    Output format (default: text)",
    "  --fail-on   Exit 1 when findings meet this severity (default: high)",
    "  --framework Add informative mapping to NIST AI RMF 1.0",
    "  --help      Show this help (can be used without a command)",
    "",
    "Commands:",
    "  test        Run the Verifii test suite",
    "  threat status  Show bundled threat-definition version and sources",
    "",
    "Scans run locally. Threat definitions are bundled; `threat status` shows their version and sources.",
    "Symlinks are not followed; common dependency/build folders are skipped.",
    ""
  ].join("\n");
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath && pathToFileURL(invokedPath).href === import.meta.url) {
  const code = await main(process.argv.slice(2));
  process.exitCode = code;
}
