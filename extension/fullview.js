const API_URL = "http://127.0.0.1:5000/predict";
const URL_LENGTH_THRESHOLD = 75;

function getUrlParameter(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

function extractFeatures(url) {
  let features = new Array(48).fill(0);

  try {
    let parsedUrl = new URL(url);
    features[0] = (parsedUrl.hostname.match(/\./g) || []).length;
    let hostnameParts = parsedUrl.hostname.split('.');
    features[1] = Math.max(0, hostnameParts.length - 2);
    features[2] = parsedUrl.pathname.split('/').filter(p => p).length;
    features[3] = url.length;
    features[4] = (url.match(/-/g) || []).length;
    features[5] = (parsedUrl.hostname.match(/-/g) || []).length;
    features[6] = url.includes('@') ? 1 : 0;
    features[7] = url.includes('~') ? 1 : 0;
    features[8] = (url.match(/_/g) || []).length;
    features[9] = (url.match(/%/g) || []).length;
    features[10] = parsedUrl.search ? parsedUrl.search.split('&').length : 0;
    features[11] = (parsedUrl.search.match(/&/g) || []).length;
    features[12] = url.includes('#') ? 1 : 0;
    features[13] = (url.match(/\d/g) || []).length;
    features[14] = parsedUrl.protocol === 'https:' ? 0 : 1;
    features[20] = parsedUrl.hostname.length;
    features[21] = parsedUrl.pathname.length;
    features[22] = parsedUrl.search.length;
  } catch (e) {
    console.error('URL parsing failed', e);
  }

  return features;
}

function formatPercentage(value) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "N/A";
  }
  return `${Math.round(value * 100)}%`;
}

function buildFeatureTable(features) {
  let html = `
    <div class="features-title">Feature-by-feature analysis</div>
    <div class="features-table-wrapper">
      <table class="features-table">
        <thead>
          <tr>
            <th>Feature</th>
            <th>Value</th>
            <th>Threshold / Reference</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
  `;

  features.forEach(row => {
    let reference = row.reference !== null && row.reference !== undefined ? row.reference : "No fixed threshold";
    html += `
      <tr>
        <td>${row.name}</td>
        <td>${row.value}</td>
        <td>${reference}</td>
        <td class="status ${row.status.toLowerCase().replace(/ /g, "-")}">${row.status}</td>
      </tr>
    `;
  });

  html += `
        </tbody>
      </table>
    </div>
  `;

  return html;
}

function buildSummaryCard(data) {
  const summary = data.summary || {};
  const confidence = formatPercentage(summary.confidence);
  const result = summary.result || data.prediction;
  const brief = summary.brief || data.explanation || "No summary available.";
  const overall = summary.overall || {};

  const suspiciousCount = overall.suspicious_count ?? 0;
  const normalCount = overall.normal_count ?? 0;
  const modelEvaluated = overall.model_evaluated_count ?? 0;
  const mostSuspicious = (overall.most_important_suspicious || []).join(", ") || "None";
  const mostLegitimate = (overall.most_important_legitimate || []).join(", ") || "None";
  const reputation = data.domain_reputation || {};
  const reputationSignals = (reputation.signals || []).join(" ") || "No page-content signals were available.";

  let highlights = `
    <div class="summary-section">
      <div><strong>Why Phishing:</strong> ${summary.why_phishing || "No suspicious evidence was identified."}</div>
      <div><strong>Why Legitimate:</strong> ${summary.why_legitimate || "No positive evidence was identified."}</div>
    </div>
  `;

  let overallHtml = `
    <div class="summary-section">
      <div><strong>Suspicious indicators:</strong> ${suspiciousCount}</div>
      <div><strong>Normal indicators:</strong> ${normalCount}</div>
      <div><strong>Model-evaluated indicators:</strong> ${modelEvaluated}</div>
      <div><strong>Most important suspicious:</strong> ${mostSuspicious}</div>
      <div><strong>Most important legitimate:</strong> ${mostLegitimate}</div>
    </div>
  `;

  return {
    result,
    confidence,
    brief,
    highlights,
    overallHtml,
    reputationHtml: `
      <div class="summary-section domain-reputation">
        <div><strong>Domain reputation:</strong> ${reputation.verdict || "Unavailable"}</div>
        <div><strong>Page-content evidence:</strong> ${reputationSignals}</div>
      </div>
    `,
    featuresHtml: buildFeatureTable(summary.features || []),
  };
}

function buildRiskVisualization(data) {
  const summary = data.summary || {};
  const overall = summary.overall || {};
  const suspicious = Number(overall.suspicious_count || 0);
  const normal = Number(overall.normal_count || 0);
  const evaluated = Number(overall.model_evaluated_count || 0);
  const total = Math.max(suspicious + normal + evaluated, 1);
  const confidence = Number(summary.confidence ?? data.confidence ?? 0);
  const confidencePercent = Math.max(0, Math.min(100, Math.round(confidence * 100)));
  const verdictClass = data.prediction === "Phishing Website" ? "risk-danger" : "risk-safe";

  const bar = (label, value, className) => `
    <div class="risk-bar-row">
      <div class="risk-bar-label"><span>${label}</span><strong>${value}</strong></div>
      <div class="risk-bar-track"><span class="risk-bar-fill ${className}" style="width: ${Math.round((value / total) * 100)}%"></span></div>
    </div>
  `;

  return `
    <section class="risk-panel ${verdictClass}">
      <div class="risk-panel-heading">
        <div>
          <span class="risk-kicker">Risk overview</span>
          <h2>Detection signals</h2>
        </div>
        <div class="confidence-ring" style="--confidence: ${confidencePercent}%">
          <span>${confidencePercent}%</span>
        </div>
      </div>
      <div class="risk-panel-grid">
        <div class="risk-bars">
          ${bar("Suspicious", suspicious, "risk-fill-danger")}
          ${bar("Normal", normal, "risk-fill-safe")}
          ${bar("Model evaluated", evaluated, "risk-fill-neutral")}
        </div>
        <div class="risk-legend">
          <span><i class="legend-dot danger"></i>Phishing signals</span>
          <span><i class="legend-dot safe"></i>Normal signals</span>
          <span><i class="legend-dot neutral"></i>Model-only signals</span>
        </div>
      </div>
    </section>
  `;
}

function renderReport(data, url) {
  const loadingMessage = document.getElementById("loadingMessage");
  const reportContainer = document.getElementById("reportContainer");
  const predictionDiv = document.getElementById("predictionResult");
  const riskVisualization = document.getElementById("riskVisualization");
  const summaryCard = document.getElementById("summaryCard");
  const explanationDiv = document.getElementById("explanationText");
  const warningDiv = document.getElementById("warningText");
  const navigationActions = document.getElementById("navigationActions");
  const continueToSite = document.getElementById("continueToSite");
  const returnToPrevious = document.getElementById("returnToPrevious");

  loadingMessage.style.display = "none";
  reportContainer.style.display = "block";
  document.getElementById("pageUrl").textContent = url;

  predictionDiv.innerText = data.prediction;
  predictionDiv.className = data.prediction === "Phishing Website" ? "prediction-box phishing" : "prediction-box legitimate";
  riskVisualization.innerHTML = buildRiskVisualization(data);

  if (data.explanation) {
    explanationDiv.innerHTML = `<strong>Why:</strong> ${data.explanation}`;
    explanationDiv.style.display = "block";
  } else {
    explanationDiv.style.display = "none";
  }

  const cardData = buildSummaryCard(data);
  summaryCard.innerHTML = `
    <div class="summary-header">🤖 AI Security Summary</div>
    <div class="summary-row"><strong>Final result:</strong> ${cardData.result}</div>
    <div class="summary-row"><strong>Confidence:</strong> ${cardData.confidence}</div>
    <div class="summary-brief"><strong>Brief Summary:</strong> ${cardData.brief}</div>
    ${cardData.highlights}
    ${cardData.overallHtml}
    ${cardData.reputationHtml}
    ${cardData.featuresHtml}
  `;

  const isUrlLengthSuspicious = url.length > URL_LENGTH_THRESHOLD;
  if (isUrlLengthSuspicious) {
    warningDiv.innerText = "⚠️ Warning: URL length exceeds the threshold.";
    warningDiv.style.display = "block";
  } else {
    warningDiv.style.display = "none";
  }

  navigationActions.style.display = "flex";
  continueToSite.style.display = data.prediction === "Legitimate Website" ? "inline-flex" : "none";
  continueToSite.onclick = () => {
    window.location.href = url;
  };
  returnToPrevious.onclick = () => history.back();
}

function displayError(message) {
  const loadingMessage = document.getElementById("loadingMessage");
  loadingMessage.textContent = message;
  loadingMessage.style.color = "#d32f2f";
}

window.addEventListener("load", function () {
  const siteUrl = getUrlParameter("siteUrl");
  if (!siteUrl) {
    displayError("No URL was provided to analyze.");
    return;
  }

  const features = extractFeatures(siteUrl);

  fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: siteUrl })
  })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        displayError(`Error: ${data.error}`);
      } else {
        renderReport(data, siteUrl);
      }
    })
    .catch(error => {
      displayError(`Network error: ${error.message}`);
    });
});