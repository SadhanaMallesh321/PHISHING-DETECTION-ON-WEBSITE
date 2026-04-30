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

document.getElementById("check").addEventListener("click", function () {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    let url = tabs[0].url;
    let features = extractFeatures(url);

    fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        features: features
      })
    })
    .then(response => response.json())
    .then(data => {
      document.getElementById("result").innerText = data.prediction;
    })
    .catch(error => {
      document.getElementById("result").innerText = "Error: " + error.message;
    });
  });
});