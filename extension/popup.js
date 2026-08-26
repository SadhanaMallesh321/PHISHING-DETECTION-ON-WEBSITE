const URL_LENGTH_THRESHOLD = 75; // Set the URL length threshold here

function extractFeatures(url) {
  let features = new Array(48).fill(0);

  try {
    let parsedUrl = new URL(url);

    // NumDots (index 0)
    features[0] = (parsedUrl.hostname.match(/\./g) || []).length;

    // SubdomainLevel (index 1) - approximate
    let hostnameParts = parsedUrl.hostname.split('.');
    features[1] = Math.max(0, hostnameParts.length - 2);

    // PathLevel (index 2)
    features[2] = parsedUrl.pathname.split('/').filter(p => p).length;

    // UrlLength (index 3)
    features[3] = url.length;

    // NumDash (index 4)
    features[4] = (url.match(/-/g) || []).length;

    // NumDashInHostname (index 5)
    features[5] = (parsedUrl.hostname.match(/-/g) || []).length;

    // AtSymbol (index 6)
    features[6] = url.includes('@') ? 1 : 0;

    // TildeSymbol (index 7)
    features[7] = url.includes('~') ? 1 : 0;

    // NumUnderscore (index 8)
    features[8] = (url.match(/_/g) || []).length;

    // NumPercent (index 9)
    features[9] = (url.match(/%/g) || []).length;

    // NumQueryComponents (index 10)
    features[10] = parsedUrl.search ? parsedUrl.search.split('&').length : 0;

    // NumAmpersand (index 11)
    features[11] = (parsedUrl.search.match(/&/g) || []).length;

    // NumHash (index 12)
    features[12] = url.includes('#') ? 1 : 0;

    // NumNumericChars (index 13)
    features[13] = (url.match(/\d/g) || []).length;

    // NoHttps (index 14) - 1 if not https
    features[14] = parsedUrl.protocol === 'https:' ? 0 : 1;

    // HostnameLength (index 20)
    features[20] = parsedUrl.hostname.length;

    // PathLength (index 21)
    features[21] = parsedUrl.pathname.length;

    // QueryLength (index 22)
    features[22] = parsedUrl.search.length;

    // Add more features as needed...

  } catch (e) {
    // If URL parsing fails, keep zeros
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
    featuresHtml: buildFeatureTable(summary.features || []),
  };
}

document.getElementById("check").addEventListener("click", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    let url = tabs[0].url;
    let fullviewUrl = chrome.runtime.getURL("fullview.html") + "?siteUrl=" + encodeURIComponent(url);

    chrome.windows.create({
      url: fullviewUrl,
      type: "popup",
      state: "fullscreen"
    });
  });
});