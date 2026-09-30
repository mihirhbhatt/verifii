# Verifii — AI supply chain security

Verifii is a local-first security scanner for AI artifacts and RAG content. This MVP includes a CLI for developer and CI workflows plus a browser dashboard. Both reuse the same heuristic scanner, and file contents stay on the machine running the scan.

Requires Node.js 18 or later. No package installation is necessary.

## CLI

Scan a file:

```sh
verifii cli --scan path/to/document.md
```

Scan a project directory recursively:

```sh
verifii cli --scan
```

Use JSON output for scripts and integrations:

```sh
verifii cli --scan ./artifacts --format json
```

Request informative NIST AI RMF function mapping in the report:

```sh
verifii cli --scan ./artifacts --framework nist-ai-rmf --format json
```

If no path is supplied, Verifii scans the current working directory. The CLI exits with **0** when no finding meets the configured threshold, **1** when a finding meets it, and **2** for invalid arguments or file access errors. The default threshold is high (critical/high). Change it explicitly with `--fail-on critical|high|medium|low|never`. For example, `verifii cli --scan . --fail-on medium` fails a CI check when a medium or higher finding exists. `verifii --help` prints usage. The shorter `verifii scan <path>` form is also supported.

Directory scans skip `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.next`, `dist`, and `build`. Symbolic links are not followed. Individual files above 25 MB are marked as needing review, not clean. PDF files are reported as not inspected because this MVP does not include a PDF parser.

To install the CLI command locally from this checkout:

```sh
npm link
verifii cli --scan
```

## Curated threat definitions

`threat-catalog.js` versions the shipped heuristic definitions, explains their limitations, and records the public sources that inform their review. Check the bundled catalog with:

```sh
verifii threat status
```

This MVP **does not fetch threat feeds or automatically update rules**. NIST and OWASP references inform Verifii's curated rule reviews; they are not executable signatures or guarantees that a threat is detected. Definitions change with code releases, are tested locally, and reports include their catalog version. A future updater should distribute signed, schema-validated, non-executable rule packs, verify them before activation, and keep a cached offline copy.

## NIST AI RMF reporting

`--framework nist-ai-rmf` annotates observed scanner findings with relevant high-level **GOVERN, MAP, MEASURE, and MANAGE** functions. It also lists major organizational and system-level areas the scanner did not assess. JSON and text output, as well as browser-exported reports, include this disclaimer and the threat-catalog version.

This is **informative alignment, not NIST AI RMF compliance, conformity, certification, or a readiness score**. The NIST AI RMF is voluntary guidance; NIST's official page says version 1.0 is being revised. File-level heuristics cannot evaluate organizational governance, intended system use, stakeholder impacts, risk tolerance, model validity, human oversight, or operational risk-management processes. Validate the framework version and mapping against the current NIST publications and your organization's context before using it for governance or audit evidence.

- [NIST AI Risk Management Framework (AI RMF 1.0)](https://doi.org/10.6028/NIST.AI.100-1)
- [NIST Generative AI Profile (NIST AI 600-1)](https://doi.org/10.6028/NIST.AI.600-1)
- [NIST AI RMF page and revision status](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## Browser dashboard

```sh
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The static server binds to loopback only; scanning runs in the browser. Use the artifact filters and **Export report** to download a JSON summary.

## What it checks

- **Text, datasets, and RAG content:** instruction-override language, email addresses, Social Security number-shaped values, common API-token shapes, hidden/commented HTML, and external URLs.
- **Notebooks and Python source:** shell/magic commands, dynamic code execution, and unsafe deserialization calls such as `pickle.load()` and `torch.load()`.
- **Serialized models:** scans visible strings in model bytes for code-like pickle indicators without deserializing or executing the file. For `.safetensors`, checks the declared header length and scans readable metadata.

## Limitations

This is a product prototype, not a malware scanner, full static analyzer, or security certification. Rules match suspicious patterns and may produce false positives or miss threats. A clean result means only that the included checks did not match. This MVP does not load models, execute notebook code, unpack archives, inspect PDF contents, detect model backdoors, identify poisoned labels, perform deep PII recognition, verify dependency CVEs, or send data to external threat-intelligence services. Review findings and scan outputs with trusted, format-aware security tooling before using artifacts in production.

## Growing this into a startup

Use the pasted product brief as a direction, not a claim about features this prototype already has. Keep each step small and validate it with design partners:

1. **MVP (now):** local CLI/dashboard scans, curated rule metadata, basic JSON output, and informative NIST AI RMF function mapping.
2. **Format coverage:** validate demand before adding safe archive inspection, structured Parquet/Excel/PDF parsing, deeper model formats, and dataset-quality or poisoning checks. Add resource limits and parser-specific adversarial fixtures.
3. **Supply chain and agent tools:** evaluate dependency advisory sources, model provenance, MCP configuration checks, and static analysis of agent-tool code. These need explicit source attribution, test cases, and well-defined false-positive behavior.
4. **Team workflows:** add CI examples, SARIF/reporting integrations, stable schemas, severity gates, and baselines.
5. **RAG firewall:** build opt-in ingestion hooks for the frameworks/vector stores pilot users actually run; test block/allow behavior before advertising runtime protection.
6. **Governance and hosted product:** improve framework mappings with traceable, reviewed evidence and organizational inputs. Consider hosted identity, tenant isolation, audit trails, deployment, and pricing only after validating customer needs.

Do not label model backdoors, CVE coverage, MCP hijacking, RAG blocking, or regulatory compliance as supported until their dedicated analysis, tests, and operational controls exist. File privacy and retention should be explicit product choices, not accidental defaults.

The scanner, versioned threat catalog, CLI, browser UI, and static server are separate modules. This is a small starting point, not a production-ready SaaS or a promise that future phases are already implemented.

## Tests

Run the test suite through the Verifii CLI:

```sh
verifii test
```

The project-level npm command remains available for CI and contributors:

```sh
npm test
```
