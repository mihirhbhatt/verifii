import { getThreatDefinition, THREAT_CATALOG } from "./threat-catalog.js";

const SUPPORTED_TEXT = new Set([
  ".ipynb", ".py", ".pyc", ".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin",
  ".safetensors", ".h5", ".hdf5", ".keras", ".onnx", ".csv", ".tsv", ".json",
  ".jsonl", ".ndjson", ".txt", ".md", ".html", ".htm", ".xml", ".yaml", ".yml",
  ".toml", ".log", ".pdf"
]);

const CATEGORY_BY_EXTENSION = {
  ".ipynb": "Notebook", ".py": "Source code", ".pyc": "Model / binary", ".pkl": "Model / binary",
  ".pickle": "Model / binary", ".joblib": "Model / binary", ".pt": "Model / binary",
  ".pth": "Model / binary", ".bin": "Model / binary", ".safetensors": "Model / binary",
  ".h5": "Model / binary", ".hdf5": "Model / binary", ".keras": "Model / binary",
  ".onnx": "Model / binary", ".csv": "Dataset", ".tsv": "Dataset", ".json": "Dataset",
  ".jsonl": "Dataset", ".ndjson": "Dataset", ".pdf": "RAG document", ".md": "RAG document",
  ".txt": "RAG document", ".html": "RAG document", ".htm": "RAG document",
  ".xml": "RAG document", ".yaml": "Configuration", ".yml": "Configuration",
  ".toml": "Configuration", ".log": "Log file"
};

const RULES = [
  {
    id: "prompt-injection",
    title: "Prompt injection",
    severity: "high",
    pattern: /\b(ignore|disregard|forget|override|bypass)\b.{0,80}\b(previous|prior|above|all|system|developer)\b.{0,60}\b(instructions?|rules?|prompts?|messages?)\b|\b(system prompt|developer message)\b.{0,80}\b(reveal|exfiltrate|override|ignore|disregard)\b|\b(reveal|print|show|expose)\b.{0,50}\b(system prompt|hidden instructions|secret key|credentials?)\b/gi,
    description: "Text contains language commonly used to override an AI assistant’s instructions."
  },
  {
    id: "secret",
    title: "Potential exposed secret",
    severity: "high",
    pattern: /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,})\b/g,
    description: "A token-like value matches a common cloud, source-control, or API key format."
  },
  {
    id: "ssn",
    title: "Possible Social Security number",
    severity: "high",
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    description: "A value matches the format of a US Social Security number."
  },
  {
    id: "email",
    title: "Email address",
    severity: "low",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    description: "An email address may be personally identifiable information."
  },
  {
    id: "python-execution",
    title: "Dynamic code execution",
    severity: "high",
    pattern: /\b(?:eval|exec)\s*\(|\bsubprocess\.(?:Popen|run|call|check_output)\s*\(|\bos\.(?:system|popen|exec\w*)\s*\(/g,
    description: "Code dynamically executes expressions or starts system processes; review the source and its inputs."
  },
  {
    id: "unsafe-deserialization",
    title: "Unsafe deserialization",
    severity: "high",
    pattern: /\b(?:pickle|joblib)\.(?:load|loads)\s*\(|\btorch\.load\s*\(/g,
    description: "A loader may execute code embedded in an untrusted serialized model."
  },
  {
    id: "notebook-shell",
    title: "Notebook shell command",
    severity: "medium",
    pattern: /^\s*[!%]{1,2}\s*(?:sh|bash|pip|conda|curl|wget|chmod|python)\b/gm,
    description: "A notebook cell invokes a shell command or environment magic."
  },
  {
    id: "hidden-content",
    title: "Hidden or commented content",
    severity: "medium",
    pattern: /<!--[\s\S]{0,3000}?(?:ignore|disregard|system prompt|instructions?)[\s\S]{0,3000}?-->|(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?|color\s*:\s*(?:white|#fff(?:fff)?))[^<\n]{0,300}/gi,
    description: "Hidden HTML or styling could conceal instructions from a human reviewer."
  },
  {
    id: "external-link",
    title: "External URL",
    severity: "low",
    pattern: /\bhttps?:\/\/[^\s<>"')\]]+/gi,
    description: "An external URL may be benign; verify that its destination is trusted."
  }
];

const BINARY_EXTENSIONS = new Set([
  ".pyc", ".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin",
  ".safetensors", ".h5", ".hdf5", ".keras", ".onnx"
]);
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function extensionOf(name) {
  const index = name.lastIndexOf(".");
  return index < 0 ? "" : name.slice(index).toLowerCase();
}

function contextAt(text, start, end) {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const lineEndIndex = text.indexOf("\n", end);
  const lineEnd = lineEndIndex < 0 ? text.length : lineEndIndex;
  return text.slice(lineStart, lineEnd).trim().slice(0, 180);
}

function findingsFromText(text, { includeCode = false, includeNotebook = false } = {}) {
  const findings = [];
  for (const rule of RULES) {
    if (!includeCode && ["python-execution", "unsafe-deserialization"].includes(rule.id)) continue;
    if (!includeNotebook && rule.id === "notebook-shell") continue;
    rule.pattern.lastIndex = 0;
    let match;
    while ((match = rule.pattern.exec(text)) !== null) {
      const prefix = text.slice(0, match.index);
      const line = (prefix.match(/\n/g) || []).length + 1;
      findings.push({
        id: `${rule.id}-${match.index}`,
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        description: rule.description,
        line,
        snippet: contextAt(text, match.index, match.index + match[0].length)
      });
      if (match[0].length === 0) rule.pattern.lastIndex++;
    }
  }
  return findings;
}

function notebookText(content) {
  try {
    const notebook = JSON.parse(content);
    if (!Array.isArray(notebook.cells)) return { text: content, error: true };
    return {
      text: notebook.cells.map((cell) => {
        const source = Array.isArray(cell.source) ? cell.source.join("") : cell.source;
        return typeof source === "string" ? source : "";
      }).join("\n"),
      error: false
    };
  } catch {
    return { text: content, error: true };
  }
}

function decodeVisibleBytes(buffer) {
  const bytes = new Uint8Array(buffer);
  let text = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    const chunk = bytes.subarray(index, Math.min(index + chunkSize, bytes.length));
    text += String.fromCharCode(...chunk);
  }
  return text.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, " ");
}

function modelFindings(name, buffer) {
  const ext = extensionOf(name);
  const findings = [];
  if ([...BINARY_EXTENSIONS].includes(ext)) {
    const visibleText = decodeVisibleBytes(buffer);
    const unsafeMatches = [...visibleText.matchAll(/\b(?:GLOBAL|STACK_GLOBAL|REDUCE|BUILD|torch\.load|pickle\.load|os\.system|subprocess)\b/g)];
    if (unsafeMatches.length > 0) {
      findings.push({
        id: `pickle-indicator-0`,
        ruleId: "serialized-code-indicator",
        title: "Executable serialization indicator",
        severity: "high",
        description: `Found ${unsafeMatches.length} code-like serialization indicator(s) in the binary. This is a heuristic, not proof of malicious behavior.`,
        line: 1,
        snippet: [...new Set(unsafeMatches.slice(0, 4).map((match) => match[0]))].join(", ")
      });
    }
  }
  if (ext === ".safetensors" && buffer.byteLength >= 8) {
    const headerLength = new DataView(buffer).getBigUint64(0, true);
    if (headerLength > BigInt(buffer.byteLength - 8) || headerLength > 10000000n) {
      findings.push({
        id: "invalid-safetensors-header",
        ruleId: "invalid-model-header",
        title: "Invalid model header",
        severity: "medium",
        description: "The safetensors header length is invalid or exceeds the 10 MB inspection limit.",
        line: 1,
        snippet: `Header length: ${headerLength} bytes`
      });
    } else {
      try {
        const header = new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(buffer, 8, Number(headerLength)));
        const headerFindings = findingsFromText(header);
        for (const finding of headerFindings) {
          if (finding.ruleId !== "email" && finding.ruleId !== "external-link") {
            findings.push({ ...finding, id: `header-${finding.id}` });
          }
        }
      } catch {
        findings.push({
          id: "invalid-safetensors-json",
          ruleId: "invalid-model-header",
          title: "Unreadable model header",
          severity: "medium",
          description: "The safetensors metadata header is not valid UTF-8.",
          line: 1,
          snippet: "Unable to decode the declared header as UTF-8."
        });
      }
    }
  }
  return findings;
}

function summaryStatus(findings, unsupported = false) {
  if (unsupported && findings.length === 0) return "unsupported";
  if (findings.some((finding) => finding.severity === "critical")) return "critical";
  if (findings.some((finding) => finding.severity === "high")) return "high";
  if (findings.some((finding) => finding.severity === "medium")) return "medium";
  return findings.length > 0 ? "low" : "clean";
}

function addThreatMetadata(findings) {
  for (const finding of findings) {
    const definition = getThreatDefinition(finding.ruleId);
    finding.threatDefinition = definition
      ? {
          confidence: definition.confidence,
          sourceIds: definition.sourceIds,
          nistFunctions: definition.nistFunctions,
          rationale: definition.rationale
        }
      : null;
  }
  return findings;
}

export function scanBuffer(name, size, buffer) {
  const ext = extensionOf(name);
  const category = CATEGORY_BY_EXTENSION[ext] || "Unknown";
  if (!SUPPORTED_TEXT.has(ext)) {
    return {
      name, size, category, findings: [], status: "unsupported",
      note: "This file format is not inspected by this MVP.",
      scannedAt: new Date().toISOString()
    };
  }
  if (ext === ".pdf") {
    const findings = addThreatMetadata([{
      id: "pdf-parser-unavailable", ruleId: "unsupported-parser",
      title: "PDF content not inspected", severity: "medium",
      description: "This MVP does not include a PDF parser. Convert the document to plain text for content scanning.",
      line: null, snippet: ""
    }]);
    return {
      name, size, category,
      findings,
      status: "medium", scannedAt: new Date().toISOString()
    };
  }
  if (size > 25 * 1024 * 1024) {
    return {
      name, size, category, findings: [], status: "unsupported",
      note: "Files over 25 MB are not inspected by this MVP.",
      scannedAt: new Date().toISOString()
    };
  }
  let findings;
  if (ext === ".safetensors" || BINARY_EXTENSIONS.has(ext)) {
    findings = modelFindings(name, buffer);
  } else {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(buffer);
    if (ext === ".ipynb") {
      const extracted = notebookText(text);
      findings = findingsFromText(extracted.text, { includeCode: true, includeNotebook: true });
      if (extracted.error) {
        findings.push({
          id: "invalid-notebook",
          ruleId: "invalid-notebook",
          title: "Notebook structure could not be parsed",
          severity: "medium",
          description: "The file is not valid notebook JSON. Its raw text was scanned, but notebook cells could not be identified.",
          line: null,
          snippet: ""
        });
      }
    } else {
      findings = findingsFromText(text, { includeCode: ext === ".py" });
    }
  }
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.line ?? 0) - (b.line ?? 0));
  addThreatMetadata(findings);
  return {
    name,
    size,
    category,
    findings,
    status: summaryStatus(findings),
    threatCatalog: { id: THREAT_CATALOG.id, version: THREAT_CATALOG.version },
    scannedAt: new Date().toISOString()
  };
}

export async function scanFile(file) {
  return scanBuffer(file.name, file.size, await file.arrayBuffer());
}

export function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
