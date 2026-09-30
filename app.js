import { formatSize, scanFile } from "./scanner.js";
import { createNistAlignment, THREAT_CATALOG } from "./threat-catalog.js";

const state = {
  artifacts: [],
  filter: "all",
  query: "",
  scanning: false,
  toastTimer: null
};

const elements = {
  fileInput: document.querySelector("#file-input"),
  dropzone: document.querySelector("#dropzone"),
  rows: document.querySelector("#artifact-rows"),
  empty: document.querySelector("#empty-state"),
  search: document.querySelector("#search-input"),
  filterButton: document.querySelector("#filter-button"),
  filterRow: document.querySelector("#filter-row"),
  exportButton: document.querySelector("#export-button"),
  toast: document.querySelector("#toast")
};

function kindFor(category) {
  if (category === "Notebook" || category === "Source code") return "notebook";
  if (category === "Dataset") return "dataset";
  if (category === "Model / binary") return "model";
  return "document";
}

function extensionLabel(name) {
  const extension = name.includes(".") ? name.split(".").pop().toUpperCase() : "FILE";
  return extension.slice(0, 5);
}

function safeText(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function timeLabel(isoString) {
  if (!isoString) return "—";
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(isoString).getTime()) / 60000));
  if (minutes < 1) return "Just now";
  if (minutes === 1) return "1 min ago";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours === 1) return "1 hour ago";
  if (hours < 24) return `${hours} hours ago`;
  return new Date(isoString).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function findingsBySeverity(artifact, severity) {
  return artifact.findings.filter((finding) => finding.severity === severity).length;
}

function rowMatchesFilter(artifact) {
  switch (state.filter) {
    case "critical":
      return artifact.status === "critical";
    case "high":
      return artifact.status === "high" || artifact.status === "critical";
    case "medium":
      return artifact.findings.some((finding) => finding.severity === "medium");
    case "clean":
      return artifact.status === "clean";
    case "unsupported":
      return artifact.status === "unsupported";
    default:
      return true;
  }
}

function renderRow(artifact) {
  const kind = kindFor(artifact.category);
  const statusLabels = {
    critical: "Critical risk", high: "High risk", medium: "Review", low: "Low risk",
    clean: "No findings", unsupported: "Needs review"
  };
  const findingCounts = ["critical", "high", "medium", "low"]
    .map((severity) => ({ severity, count: findingsBySeverity(artifact, severity) }))
    .filter((item) => item.count > 0);
  const findingsMarkup = findingCounts.length
    ? `<span class="finding-pills">${findingCounts.map(({ severity, count }) => `<span class="finding-pill ${severity}">${count} ${severity}</span>`).join("")}</span>`
    : artifact.status === "unsupported"
      ? `<span class="no-findings">Not inspected</span>`
      : `<span class="no-findings">—</span>`;
  const details = artifact.status === "unsupported"
    ? (artifact.note || "File format is not supported by this MVP.")
    : `${artifact.findings.length} finding${artifact.findings.length === 1 ? "" : "s"}`;
  return `<tr>
    <td><div class="artifact-cell"><span class="file-icon" data-kind="${kind}">${safeText(extensionLabel(artifact.name))}</span><span class="file-meta"><strong title="${safeText(artifact.name)}">${safeText(artifact.name)}</strong><small>${safeText(formatSize(artifact.size))}</small></span></div></td>
    <td><span class="type-label"><i class="type-dot" data-kind="${kind}"></i>${safeText(artifact.category)}</span></td>
    <td><span class="status-badge status-${artifact.status}" title="${safeText(details)}"><i></i>${statusLabels[artifact.status]}</span></td>
    <td>${findingsMarkup}</td>
    <td class="time-cell">${safeText(timeLabel(artifact.scannedAt))}</td>
    <td><button class="row-menu" type="button" data-artifact-id="${safeText(artifact.id)}" aria-label="View findings for ${safeText(artifact.name)}" title="View findings">›</button></td>
  </tr>`;
}

function renderRows() {
  const query = state.query.trim().toLowerCase();
  const visible = state.artifacts.filter((artifact) =>
    rowMatchesFilter(artifact) && artifact.name.toLowerCase().includes(query)
  );
  elements.rows.innerHTML = visible.map(renderRow).join("");
  elements.empty.hidden = visible.length !== 0;
  elements.rows.closest("table").hidden = visible.length === 0;
  document.querySelector("#table-summary").textContent = visible.length === state.artifacts.length
    ? `Showing ${visible.length} artifact${visible.length === 1 ? "" : "s"}`
    : `Showing ${visible.length} of ${state.artifacts.length} artifacts`;
  document.querySelector("#artifact-header-count").textContent = state.artifacts.length;
  document.querySelector("#nav-artifact-count").textContent = state.artifacts.length;
  elements.rows.querySelectorAll("[data-artifact-id]").forEach((button) => {
    button.addEventListener("click", () => showArtifactDetails(button.dataset.artifactId));
  });
  updateSummary();
}

function updateSummary() {
  const findings = state.artifacts.flatMap((artifact) => artifact.findings);
  const count = (severity) => findings.filter((finding) => finding.severity === severity).length;
  const critical = count("critical");
  const high = count("high");
  const medium = count("medium");
  const low = count("low");
  const total = findings.length;
  const attention = state.artifacts.filter((artifact) => ["critical", "high"].includes(artifact.status)).length;
  document.querySelector("#stat-scanned").textContent = state.artifacts.length;
  document.querySelector("#stat-attention").textContent = attention;
  document.querySelector("#stat-findings").textContent = total;
  document.querySelector("#stat-last-scan").textContent = state.artifacts.length ? "Just now" : "—";
  document.querySelector("#count-critical").textContent = critical;
  document.querySelector("#count-high").textContent = high;
  document.querySelector("#count-medium").textContent = medium;
  document.querySelector("#count-low").textContent = low;
  document.querySelector("#exposure-total").textContent = total;
  document.querySelector("#exposure-chart").setAttribute("aria-label", `${total} findings: ${critical} critical, ${high} high, ${medium} medium, ${low} low`);
  document.querySelector("#exposure-message").textContent = attention
    ? `${attention} artifact${attention === 1 ? "" : "s"} need${attention === 1 ? "s" : ""} a closer look.`
    : total
      ? "Review the findings before sharing these artifacts."
      : "Your supply chain is looking good.";
  const colors = ["#c96762", "#e39b66", "#e0bf67", "#63a98e"];
  const values = [critical, high, medium, low];
  const sum = total || 1;
  let current = 0;
  const segments = values.map((value, index) => {
    const start = current;
    current += (value / sum) * 360;
    return `${colors[index]} ${start}deg ${current}deg`;
  });
  document.querySelector("#exposure-chart").style.background = total
    ? `conic-gradient(${segments.join(", ")})`
    : "conic-gradient(#edf2f0 0deg 360deg)";
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => elements.toast.classList.remove("visible"), 3600);
}

function showArtifactDetails(id) {
  const artifact = state.artifacts.find((item) => item.id === id);
  if (!artifact) return;
  if (artifact.findings.length === 0) {
    showToast(artifact.status === "unsupported"
      ? `${artifact.name}: ${artifact.note || "This format needs a compatible scanner."}`
      : `${artifact.name}: no heuristic matches found. This is not a guarantee of safety.`);
    return;
  }
  const details = artifact.findings.slice(0, 4).map((finding) => {
    const location = finding.line ? ` · line ${finding.line}` : "";
    const alignment = finding.threatDefinition?.nistFunctions?.length
      ? ` · NIST AI RMF functions (informative): ${finding.threatDefinition.nistFunctions.join(", ")}`
      : "";
    return `${finding.severity.toUpperCase()} — ${finding.title}${location}: ${finding.snippet || finding.description}${alignment}`;
  });
  showToast(`${artifact.name}: ${details.join(" | ")}${artifact.findings.length > 4 ? ` (+${artifact.findings.length - 4} more)` : ""}`);
}

async function addFiles(fileList) {
  const files = Array.from(fileList);
  if (files.length === 0) return;
  if (state.scanning) {
    showToast("A scan is already in progress. Try again in a moment.");
    return;
  }
  state.scanning = true;
  let completed = 0;
  for (const file of files) {
    try {
      const result = await scanFile(file);
      result.id = `${file.name}-${file.size}-${result.scannedAt}`;
      state.artifacts = [result, ...state.artifacts.filter((item) => item.name !== file.name)];
    } catch (error) {
      console.error("Unable to inspect file", file.name, error);
      const result = {
        id: `${file.name}-${file.size}-${Date.now()}`,
        name: file.name,
        size: file.size,
        category: "Unknown",
        findings: [],
        status: "unsupported",
        note: "The browser could not read this file.",
        scannedAt: new Date().toISOString()
      };
      state.artifacts = [result, ...state.artifacts.filter((item) => item.name !== file.name)];
    }
    completed++;
    renderRows();
  }
  state.scanning = false;
  showToast(`Scan complete. ${completed} file${completed === 1 ? "" : "s"} processed locally.`);
  elements.fileInput.value = "";
}

function exportReport() {
  const report = {
    product: "Verifii browser MVP",
    generatedAt: new Date().toISOString(),
    privacy: "Files are inspected locally in this browser. This report contains filenames and findings only.",
    threatCatalog: {
      id: THREAT_CATALOG.id,
      version: THREAT_CATALOG.version,
      updatedAt: THREAT_CATALOG.updatedAt,
      updateMode: THREAT_CATALOG.updateMode,
      sources: THREAT_CATALOG.sources
    },
    frameworkAlignment: createNistAlignment(state.artifacts),
    scannerLimitations: [
      "Heuristic static checks only; a clean result is not proof that a file is safe.",
      "No model loading, execution, machine-learning backdoor detection, or dependency vulnerability lookup.",
      "PDF contents and files over 25 MB are not inspected.",
      "NIST AI RMF mapping is informative scanner evidence, not a compliance assessment."
    ],
    artifacts: state.artifacts.map(({ id, ...artifact }) => artifact)
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `verifii-report-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
  showToast("Security report exported as JSON.");
}

elements.fileInput.addEventListener("change", () => addFiles(elements.fileInput.files));
document.querySelector("#add-artifacts-button").addEventListener("click", () => elements.fileInput.click());
document.querySelector("#empty-add-button").addEventListener("click", () => elements.fileInput.click());
elements.search.addEventListener("input", () => {
  state.query = elements.search.value;
  renderRows();
});
elements.filterButton.addEventListener("click", () => {
  elements.filterRow.hidden = !elements.filterRow.hidden;
});
elements.filterRow.addEventListener("click", (event) => {
  const button = event.target.closest("[data-filter]");
  if (!button) return;
  state.filter = button.dataset.filter;
  elements.filterRow.querySelectorAll("[data-filter]").forEach((item) => item.classList.toggle("selected", item === button));
  renderRows();
});
elements.exportButton.addEventListener("click", exportReport);

for (const eventName of ["dragenter", "dragover"]) {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.add("drag-over");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.remove("drag-over");
  });
}
elements.dropzone.addEventListener("drop", (event) => addFiles(event.dataTransfer.files));

renderRows();
