export const THREAT_CATALOG = Object.freeze({
  id: "verifii-core",
  version: "0.1.0",
  updatedAt: "2026-09-30",
  updateMode: "bundled",
  summary: "Curated, heuristic checks bundled with Verifii. No remote feed is queried.",
  sources: [
    {
      id: "nist-ai-rmf",
      name: "NIST AI Risk Management Framework 1.0",
      url: "https://doi.org/10.6028/NIST.AI.100-1",
      role: "Voluntary risk-management framework; used for high-level, informative function mapping."
    },
    {
      id: "nist-genai-profile",
      name: "NIST Generative AI Profile",
      url: "https://doi.org/10.6028/NIST.AI.600-1",
      role: "Generative AI risk-management guidance; informs prompt-injection and data-risk review."
    },
    {
      id: "owasp-llm-top-10",
      name: "OWASP Top 10 for LLM Applications",
      url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
      role: "Application-security risk taxonomy; informs prompt-injection and sensitive-information checks."
    }
  ],
  definitions: [
    {
      id: "prompt-injection",
      name: "Prompt injection",
      confidence: "heuristic",
      sourceIds: ["nist-genai-profile", "owasp-llm-top-10"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "A textual signal for organizations to contextualize, test, and mitigate; a match is not proof of a successful attack."
    },
    {
      id: "secret",
      name: "Potential exposed secret",
      confidence: "heuristic",
      sourceIds: ["owasp-llm-top-10"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "A token-shaped string may warrant privacy and information-security review; the pattern does not validate whether a credential is active."
    },
    {
      id: "ssn",
      name: "Possible Social Security number",
      confidence: "heuristic",
      sourceIds: ["nist-ai-rmf"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "A possible personal identifier is a data-risk signal, not a determination that the information is real or regulated."
    },
    {
      id: "email",
      name: "Email address",
      confidence: "heuristic",
      sourceIds: ["nist-ai-rmf"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "An email-shaped value can prompt privacy review; it may be synthetic or intentionally public."
    },
    {
      id: "python-execution",
      name: "Dynamic code execution",
      confidence: "heuristic",
      sourceIds: ["owasp-llm-top-10"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "A code pattern to review in its execution context; the scanner does not determine reachability or exploitability."
    },
    {
      id: "unsafe-deserialization",
      name: "Unsafe deserialization",
      confidence: "heuristic",
      sourceIds: ["owasp-llm-top-10"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "A potentially unsafe loader pattern; the scanner does not execute or fully analyze serialized content."
    },
    {
      id: "notebook-shell",
      name: "Notebook shell command",
      confidence: "heuristic",
      sourceIds: ["owasp-llm-top-10"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "A notebook command to review for necessity, trust boundaries, and execution controls."
    },
    {
      id: "hidden-content",
      name: "Hidden or commented content",
      confidence: "heuristic",
      sourceIds: ["nist-genai-profile", "owasp-llm-top-10"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "Concealed text or styling may merit inspection when content is used in an AI system."
    },
    {
      id: "external-link",
      name: "External URL",
      confidence: "heuristic",
      sourceIds: ["nist-ai-rmf"],
      nistFunctions: ["MAP", "MANAGE"],
      rationale: "A link may be benign; review provenance and trust before ingestion or execution."
    },
    {
      id: "serialized-code-indicator",
      name: "Executable serialization indicator",
      confidence: "heuristic",
      sourceIds: ["owasp-llm-top-10"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "Visible strings in a binary suggest manual review; this check is not a pickle parser or model-malware verdict."
    },
    {
      id: "invalid-model-header",
      name: "Invalid model header",
      confidence: "heuristic",
      sourceIds: ["nist-ai-rmf"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "Malformed metadata warrants integrity and provenance review; it does not establish intent or compromise."
    },
    {
      id: "unsupported-parser",
      name: "Unsupported document parser",
      confidence: "coverage-gap",
      sourceIds: ["nist-ai-rmf"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "An uninspected format is a scanner coverage gap and must not be treated as evidence of safety."
    },
    {
      id: "invalid-notebook",
      name: "Invalid notebook structure",
      confidence: "heuristic",
      sourceIds: ["nist-ai-rmf"],
      nistFunctions: ["MAP", "MEASURE", "MANAGE"],
      rationale: "Unparseable content is a format-integrity signal; it is not a complete notebook assessment."
    }
  ]
});

export const NIST_AI_RMF = Object.freeze({
  id: "nist-ai-rmf",
  name: "NIST AI Risk Management Framework",
  version: "1.0",
  status: "voluntary; revision in progress",
  source: "https://doi.org/10.6028/NIST.AI.100-1",
  profile: {
    name: "NIST Generative AI Profile",
    version: "NIST AI 600-1",
    source: "https://doi.org/10.6028/NIST.AI.600-1"
  },
  functions: [
    { id: "GOVERN", description: "Establish and maintain AI risk-management culture, policies, and accountability." },
    { id: "MAP", description: "Understand the AI system context, intended use, impacts, and risks." },
    { id: "MEASURE", description: "Analyze, assess, benchmark, and monitor identified AI risks." },
    { id: "MANAGE", description: "Prioritize, respond to, and monitor AI risks." }
  ],
  disclaimer: "Informative mapping of scanner observations to relevant AI RMF functions only. A scan cannot establish NIST AI RMF conformity, organizational compliance, or completion of any framework outcome."
});

const definitionsById = new Map(THREAT_CATALOG.definitions.map((definition) => [definition.id, definition]));

export function getThreatDefinition(id) {
  return definitionsById.get(id) || null;
}

export function createNistAlignment(artifacts) {
  const findings = artifacts.flatMap((artifact) =>
    artifact.findings.map((finding) => ({
      path: artifact.name,
      severity: finding.severity,
      ruleId: finding.ruleId,
      title: finding.title,
      functions: getThreatDefinition(finding.ruleId)?.nistFunctions || []
    }))
  );
  return {
    framework: NIST_AI_RMF,
    evidenceCountsByFunction: Object.fromEntries(
      NIST_AI_RMF.functions.map((frameworkFunction) => [
        frameworkFunction.id,
        findings.filter((finding) => finding.functions.includes(frameworkFunction.id)).length
      ])
    ),
    scannerEvidence: findings,
    notAssessed: [
      "Organizational governance, policies, roles, accountability, or AI inventories.",
      "System purpose, context, affected stakeholders, impact assessments, or risk tolerance.",
      "Model validity, robustness, fairness, transparency, privacy controls, or human oversight.",
      "Risk treatment decisions, deployment approvals, incident response, or ongoing monitoring."
    ],
    disclaimer: NIST_AI_RMF.disclaimer
  };
}
