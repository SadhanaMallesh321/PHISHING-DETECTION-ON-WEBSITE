const params = new URLSearchParams(window.location.search);
const siteUrl = params.get("siteUrl");
const reason = params.get("reason");

document.getElementById("blockedUrl").textContent = siteUrl || "Unknown URL";
if (reason) {
  document.getElementById("blockedReason").textContent = reason;
}

document.getElementById("goBack").addEventListener("click", () => history.back());