const API_URL = "http://127.0.0.1:5000/predict";
const BLOCKED_PAGE = "blocked.html";
const checksInProgress = new Set();
const analysisCache = new Map();
const analysisInProgress = new Map();
const ANALYSIS_CACHE_TTL = 5 * 60 * 1000;

function canCheck(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
  } catch (error) {
    return false;
  }
}

function blockedPageUrl(siteUrl, reason) {
  return `${chrome.runtime.getURL(BLOCKED_PAGE)}?siteUrl=${encodeURIComponent(siteUrl)}&reason=${encodeURIComponent(reason)}`;
}

async function checkUrl(siteUrl, pageFeatures = null) {
  const requestBody = { url: siteUrl };
  if (pageFeatures && typeof pageFeatures === "object") {
    requestBody.page_features = pageFeatures;
  }
  const response = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    throw new Error(`Prediction API returned ${response.status}`);
  }

  const result = await response.json();
  if (result.error) {
    throw new Error(result.error);
  }

  const safe = result.prediction === "Legitimate Website";
  return {
    safe,
    result: result.prediction,
    domainReputation: result.domain_reputation || null
  };
}

async function analyzeUrl(siteUrl, pageFeatures = null) {
  const cacheKey = `${siteUrl}|${JSON.stringify(pageFeatures || {})}`;
  const cached = analysisCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.result;
  }
  if (analysisInProgress.has(cacheKey)) {
    return analysisInProgress.get(cacheKey);
  }

  const requestBody = { url: siteUrl };
  if (pageFeatures && typeof pageFeatures === "object") {
    requestBody.page_features = pageFeatures;
  }

  const request = fetch(`${API_URL.replace(/\/predict$/, "")}/analyze-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody)
  }).then(async response => {
    const result = await response.json();
    if (!response.ok || result.error) {
      throw new Error(result.error || `Analysis API returned ${response.status}`);
    }
    analysisCache.set(cacheKey, { expiresAt: Date.now() + ANALYSIS_CACHE_TTL, result });
    return result;
  }).finally(() => analysisInProgress.delete(cacheKey));

  analysisInProgress.set(siteUrl, request);
  return request;
}

chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0 || !canCheck(details.url) || checksInProgress.has(details.url)) {
    return;
  }

  checksInProgress.add(details.url);
  checkUrl(details.url)
    .then(result => {
      if (!result.safe) {
        const signals = result.domainReputation?.signals?.join(" ");
        chrome.tabs.update(details.tabId, {
          url: blockedPageUrl(
            details.url,
            signals || "This website was identified as a phishing site."
          )
        });
      }
    })
    .catch(error => {
      chrome.tabs.update(details.tabId, {
        url: blockedPageUrl(details.url, "The website could not be verified.")
      });
      console.error("Unable to verify website:", error);
    })
    .finally(() => checksInProgress.delete(details.url));
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "analyze-url") {
    if (!canCheck(message.url)) {
      sendResponse({ error: "Only HTTP(S) links can be analyzed." });
      return false;
    }
    analyzeUrl(message.url, message.pageFeatures || null)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true;
  }

  if (!['check-url', 'check-link'].includes(message.type) || !canCheck(message.url)) {
    sendResponse({ safe: false, reason: "This page type cannot be verified." });
    return false;
  }

  checkUrl(message.url, message.pageFeatures || null)
    .then(result => sendResponse({
      safe: result.safe,
      reason: result.result,
      domainReputation: result.domainReputation
    }))
    .catch(error => {
      console.error("Unable to verify website:", error);
      sendResponse({ safe: false, reason: "The website could not be verified." });
    });

  return true;
});