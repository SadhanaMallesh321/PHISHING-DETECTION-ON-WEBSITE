const pageUrl = window.location.href;
const hoverCache = new Map();
let hoverTimer = null;
let activeHoverLink = null;
let hoverTooltip = null;

function hideHoverTooltip() {
    if (hoverTooltip) {
        hoverTooltip.remove();
        hoverTooltip = null;
    }
    activeHoverLink = null;
}

function showHoverTooltip(link, message, state = "") {
    hideHoverTooltip();
    const tooltip = document.createElement("div");
    tooltip.className = `phishing-hover-tooltip ${state}`;
    tooltip.textContent = message;
    document.documentElement.appendChild(tooltip);
    const rect = link.getBoundingClientRect();
    const left = Math.min(Math.max(8, rect.left), window.innerWidth - tooltip.offsetWidth - 8);
    const top = rect.bottom + 8 + tooltip.offsetHeight <= window.innerHeight
        ? rect.bottom + 8
        : Math.max(8, rect.top - tooltip.offsetHeight - 8);
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
    hoverTooltip = tooltip;
    activeHoverLink = link;
}

function analyzeHoveredLink(link) {
    const url = new URL(link.href, window.location.href).href;
    const cached = hoverCache.get(url);
    if (cached && cached.expiresAt > Date.now()) {
        showHoverTooltip(link, cached.message, cached.state);
        return;
    }

    showHoverTooltip(link, "Analyzing...", "analyzing");
    chrome.runtime.sendMessage({ type: "analyze-url", url }, result => {
        if (activeHoverLink !== link) {
            return;
        }
        if (chrome.runtime.lastError || !result || result.error) {
            showHoverTooltip(link, result?.error || "Unable to analyze this link.", "error");
            return;
        }
        const state = result.prediction === "Phishing Website"
            ? "phishing"
            : result.risk_score >= 40 ? "suspicious" : "legitimate";
        const reason = result.reasons?.[0] || "No strong risk indicators found.";
        const message = `${state[0].toUpperCase()}${state.slice(1)} | Risk ${result.risk_score}/100 | ${reason}`;
        hoverCache.set(url, { expiresAt: Date.now() + 5 * 60 * 1000, message, state });
        showHoverTooltip(link, message, state);
    });
}

document.addEventListener("mouseover", event => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const link = target?.closest("a[href]");
    if (!link || !canCheckLink(link.href) || event.relatedTarget instanceof Node && link.contains(event.relatedTarget)) {
        return;
    }
    clearTimeout(hoverTimer);
    hideHoverTooltip();
    hoverTimer = setTimeout(() => analyzeHoveredLink(link), 250);
});

document.addEventListener("mouseout", event => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const link = target?.closest("a[href]");
    if (!link || event.relatedTarget instanceof Node && link.contains(event.relatedTarget)) {
        return;
    }
    clearTimeout(hoverTimer);
    if (activeHoverLink === link) {
        hideHoverTooltip();
    }
});

function canCheckLink(url) {
    try {
        const parsedUrl = new URL(url, window.location.href);
        return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
    } catch (error) {
        return false;
    }
}

function reportUrl(siteUrl) {
    return `${chrome.runtime.getURL("fullview.html")}?siteUrl=${encodeURIComponent(siteUrl)}&fromClick=1`;
}

function collectPageFeatures() {
    const pageText = (document.body?.innerText || "").toLowerCase();
    const sensitiveWords = ["login", "verify", "password", "account", "bank", "secure", "wallet", "payment", "invoice", "urgent"];
    const links = [...document.querySelectorAll("a[href]")];
    const externalLinks = links.filter(link => {
        try {
            return new URL(link.href, window.location.href).hostname !== window.location.hostname;
        } catch (error) {
            return false;
        }
    });
    const resources = [...document.querySelectorAll("script[src], img[src], link[href], iframe[src]")];
    const externalResources = resources.filter(resource => {
        const value = resource.src || resource.href;
        try {
            return value && new URL(value, window.location.href).hostname !== window.location.hostname;
        } catch (error) {
            return false;
        }
    });
    const forms = [...document.forms];
    const formActions = forms.map(form => form.action || window.location.href);
    const externalForms = formActions.filter(action => {
        try {
            return new URL(action, window.location.href).hostname !== window.location.hostname;
        } catch (error) {
            return false;
        }
    });

    return {
        sensitive_words: sensitiveWords.filter(word => pageText.includes(word)).length,
        embedded_brand: ["paypal", "apple", "google", "microsoft", "amazon", "facebook", "instagram", "whatsapp"].some(brand => pageText.includes(brand)) ? 1 : 0,
        external_link_ratio: links.length ? externalLinks.length / links.length : 0,
        external_resource_ratio: resources.length ? externalResources.length / resources.length : 0,
        external_favicon: [...document.querySelectorAll('link[rel~="icon"]')].some(icon => {
            try {
                return new URL(icon.href, window.location.href).hostname !== window.location.hostname;
            } catch (error) {
                return false;
            }
        }) ? 1 : 0,
        insecure_forms: forms.some(form => {
            try {
                return form.method.toLowerCase() === "post" && new URL(form.action || window.location.href, window.location.href).protocol !== "https:";
            } catch (error) {
                return true;
            }
        }) ? 1 : 0,
        relative_form_action: formActions.some(action => !/^https?:\/\//i.test(action)) ? 1 : 0,
        external_form_action: externalForms.length ? 1 : 0,
        abnormal_form_action: externalForms.some(action => {
            try {
                return new URL(action, window.location.href).hostname !== window.location.hostname;
            } catch (error) {
                return true;
            }
        }) ? 1 : 0,
        null_self_redirect: links.filter(link => !link.getAttribute("href") || link.getAttribute("href") === "#").length,
        iframe: document.querySelectorAll("iframe, frame").length ? 1 : 0,
        missing_title: document.title.trim() ? 0 : 1,
        images_only_form: forms.some(form => form.querySelectorAll("input, button, textarea, select").length === 0 && form.querySelectorAll("img").length > 0) ? 1 : 0,
        meta_script_link_ratio: resources.length ? externalResources.length / resources.length : 0,
    };
}

function sendPageCheck(type, url, callback) {
    chrome.runtime.sendMessage({ type, url, pageFeatures: collectPageFeatures() }, callback);
}

document.addEventListener("click", event => {
    if (event.defaultPrevented || event.button !== 0) {
        return;
    }

    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const link = target?.closest("a[href]");
    if (!link || link.hasAttribute("download")) {
        return;
    }

    const destination = new URL(link.href, window.location.href).href;
    if (!canCheckLink(destination) || destination === window.location.href) {
        return;
    }

    event.preventDefault();
    event.stopPropagation();
    link.setAttribute("aria-busy", "true");

    chrome.runtime.sendMessage({
        type: "check-link",
        url: destination,
        pageFeatures: collectPageFeatures()
    }, response => {
        link.removeAttribute("aria-busy");
        if (chrome.runtime.lastError) {
            window.location.href = reportUrl(destination);
            return;
        }
        window.location.href = reportUrl(destination);
    });
}, true);

if (document.documentElement) {
    document.documentElement.style.visibility = "hidden";
}

function showBlockedPage(reason) {
    const head = document.createElement("head");
    const title = document.createElement("title");
    title.textContent = "Website Blocked";
    head.appendChild(title);

    const body = document.createElement("body");
    body.style.cssText = "font-family: Arial, sans-serif; margin: 0; padding: 15vh 24px; text-align: center; color: #333;";

    const heading = document.createElement("h1");
    heading.textContent = "Website blocked";
    heading.style.color = "#8e2020";
    body.appendChild(heading);

    const reasonText = document.createElement("p");
    reasonText.textContent = reason;
    body.appendChild(reasonText);

    const urlText = document.createElement("p");
    urlText.textContent = pageUrl;
    urlText.style.overflowWrap = "anywhere";
    body.appendChild(urlText);

    document.documentElement.replaceChildren(head, body);
    document.documentElement.style.visibility = "visible";
}

sendPageCheck("check-url", pageUrl, response => {
    if (chrome.runtime.lastError || !response || !response.safe) {
        showBlockedPage(response?.reason || "The website could not be verified.");
        return;
    }

    document.documentElement.style.visibility = "visible";
});