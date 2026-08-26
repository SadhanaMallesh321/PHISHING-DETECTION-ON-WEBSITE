from typing import Sequence

FEATURE_LABELS = {
    0: "NumDots",
    1: "SubdomainLevel",
    2: "PathLevel",
    3: "UrlLength",
    4: "NumDash",
    5: "NumDashInHostname",
    6: "AtSymbol",
    7: "TildeSymbol",
    8: "NumUnderscore",
    9: "NumPercent",
    10: "NumQueryComponents",
    11: "NumAmpersand",
    12: "NumHash",
    13: "NumNumericChars",
    14: "NoHttps",
    15: "RandomString",
    16: "IpAddress",
    17: "DomainInSubdomains",
    18: "DomainInPaths",
    19: "HttpsInHostname",
    20: "HostnameLength",
    21: "PathLength",
    22: "QueryLength",
    23: "DoubleSlashInPath",
    24: "NumSensitiveWords",
    25: "EmbeddedBrandName",
    26: "PctExtHyperlinks",
    27: "PctExtResourceUrls",
    28: "ExtFavicon",
    29: "InsecureForms",
    30: "RelativeFormAction",
    31: "ExtFormAction",
    32: "AbnormalFormAction",
    33: "PctNullSelfRedirectHyperlinks",
    34: "FrequentDomainNameMismatch",
    35: "FakeLinkInStatusBar",
    36: "RightClickDisabled",
    37: "PopUpWindow",
    38: "SubmitInfoToEmail",
    39: "IframeOrFrame",
    40: "MissingTitle",
    41: "ImagesOnlyInForm",
    42: "SubdomainLevelRT",
    43: "UrlLengthRT",
    44: "PctExtResourceUrlsRT",
    45: "AbnormalExtFormActionR",
    46: "ExtMetaScriptLinkRT",
    47: "PctExtNullSelfRedirectHyperlinksRT",
}

FEATURE_DESCRIPTIONS = {
    "NumDots": "Number of dots in the hostname.",
    "SubdomainLevel": "Number of subdomains detected.",
    "PathLevel": "Number of path segments after the domain.",
    "UrlLength": "Total length of the URL.",
    "NumDash": "Number of dash characters in the full URL.",
    "NumDashInHostname": "Number of dash characters inside the hostname.",
    "AtSymbol": "Whether the URL contains an '@' symbol.",
    "TildeSymbol": "Whether the URL contains a '~' character.",
    "NumUnderscore": "Number of underscore characters in the URL.",
    "NumPercent": "Number of percent-encoded characters in the URL.",
    "NumQueryComponents": "Number of query components after '?'.",
    "NumAmpersand": "Number of '&' characters in the query string.",
    "NumHash": "Whether the URL contains a fragment '#'.",
    "NumNumericChars": "Number of numeric characters in the URL.",
    "NoHttps": "Whether the URL is not HTTPS.",
    "RandomString": "Likely random or encoded sequences in the URL.",
    "IpAddress": "Whether the hostname is an IP address.",
    "DomainInSubdomains": "Whether the domain name appears again in subdomains.",
    "DomainInPaths": "Whether the domain name appears inside the path.",
    "HttpsInHostname": "Whether 'https' appears in the hostname itself.",
    "HostnameLength": "Length of the hostname.",
    "PathLength": "Length of the path portion.",
    "QueryLength": "Length of the query string.",
    "DoubleSlashInPath": "Whether a second '//' appears in the path.",
    "NumSensitiveWords": "Percentage of sensitive words found in the page (not URL-only).",
    "EmbeddedBrandName": "Whether a brand name appears embedded in the URL or page.",
    "PctExtHyperlinks": "Percentage of external links on the page.",
    "PctExtResourceUrls": "Percentage of external resource URLs.",
    "ExtFavicon": "Whether the favicon is loaded from an external source.",
    "InsecureForms": "Whether page forms submit to insecure locations.",
    "RelativeFormAction": "Whether form actions use relative paths.",
    "ExtFormAction": "Whether form actions point to external domains.",
    "AbnormalFormAction": "Whether form actions appear abnormal for the domain.",
    "PctNullSelfRedirectHyperlinks": "Percentage of self-redirect hyperlinks with empty targets.",
    "FrequentDomainNameMismatch": "Whether the displayed domain does not match the actual link domain.",
    "FakeLinkInStatusBar": "Whether links try to hide their real destination.",
    "RightClickDisabled": "Whether right-click is blocked on the page.",
    "PopUpWindow": "Whether pop-up windows are used.",
    "SubmitInfoToEmail": "Whether page forms submit data to email addresses.",
    "IframeOrFrame": "Whether the page contains iframe or frame elements.",
    "MissingTitle": "Whether the page is missing a title.",
    "ImagesOnlyInForm": "Whether a form contains only images.",
    "SubdomainLevelRT": "Relative threshold value for subdomain level.",
    "UrlLengthRT": "Relative threshold value for URL length.",
    "PctExtResourceUrlsRT": "Relative threshold for external resource URLs.",
    "AbnormalExtFormActionR": "Relative threshold for abnormal external form actions.",
    "ExtMetaScriptLinkRT": "Relative threshold for external meta/script/link content.",
    "PctExtNullSelfRedirectHyperlinksRT": "Relative threshold for null self-redirect hyperlinks.",
}

FEATURE_THRESHOLDS = {
    "UrlLength": 75,
    "NumDash": 0,
    "NumDashInHostname": 0,
    "AtSymbol": 0,
    "TildeSymbol": 0,
    "NumUnderscore": 0,
    "NumPercent": 0,
    "NoHttps": 0,
    "IpAddress": 0,
    "HostnameLength": 35,
    "PathLength": 50,
    "QueryLength": 30,
}


def _format_indicator(label: str, value: int) -> str:
    if label in {"NoHttps", "AtSymbol", "TildeSymbol", "NumHash"}:
        return f"{label} is {'on' if value else 'off'}"
    if label in {"IpAddress", "DomainInSubdomains", "DomainInPaths", "EmbeddedBrandName"}:
        return f"{label} is {'present' if value else 'not present'}"
    return f"{label}={value}"


def _feature_status(label: str, value: int) -> tuple[str, str, str | None]:
    """Return status, detailed explanation, and reference value for a feature."""
    reference = FEATURE_THRESHOLDS.get(label)
    if reference is not None:
        if label in {"NumDash", "NumDashInHostname", "AtSymbol", "TildeSymbol", "NumUnderscore", "NumPercent", "NoHttps", "IpAddress"}:
            status = "Suspicious" if value > reference else "Normal"
        else:
            status = "Suspicious" if value > reference else "Normal"
        return status, reference, FEATURE_DESCRIPTIONS.get(label, "No additional description available.")

    # For features without a fixed threshold, we still provide a descriptive explanation.
    status = "Model-evaluated"
    explanation = FEATURE_DESCRIPTIONS.get(label, "No fixed threshold is defined for this feature; the ML model evaluates it together with the other features.")
    return status, None, explanation


def _format_threshold_text(label: str, value: int) -> str:
    reference = FEATURE_THRESHOLDS.get(label)
    if reference is None:
        return "No fixed threshold is defined for this feature; the ML model evaluates it together with the other features."

    comparator = "above" if value > reference else "at or below"
    interpretation = "suspicious" if value > reference else "normal"
    return f"{value} → Threshold: {reference} → {comparator} threshold, therefore {interpretation}."


def _build_feature_row(index: int, value: int) -> dict:
    label = FEATURE_LABELS.get(index, f"Feature{index}")
    status, reference, explanation = _feature_status(label, value)
    threshold_text = _format_threshold_text(label, value)
    if reference is None:
        threshold_text = "No fixed threshold is defined for this feature; the ML model evaluates it together with the other features."

    return {
        "name": label,
        "value": value,
        "reference": reference,
        "status": status,
        "explanation": explanation,
        "threshold_text": threshold_text,
    }


def _summarize_indicators(feature_rows: list[dict]) -> tuple[list[str], list[str], list[str], list[str]]:
    suspicious = []
    normal = []
    model_evaluated = []
    important_features = []

    for row in feature_rows:
        name = row["name"]
        status = row["status"]
        if status == "Suspicious":
            suspicious.append(name)
            important_features.append(name)
        elif status == "Normal":
            normal.append(name)
        else:
            model_evaluated.append(name)

    return suspicious, normal, model_evaluated, important_features


def generate_explanation(features: Sequence[int], prediction: str) -> str:
    """Create a readable explanation for a phishing or legitimate classification."""
    if len(features) != 48:
        return "The explanation service could not analyze the provided feature set."

    feature_rows = [_build_feature_row(i, int(features[i])) for i in range(len(features))]
    suspicious, normal, model_evaluated, _ = _summarize_indicators(feature_rows)

    if prediction == "Phishing Website":
        if suspicious:
            shown = ", ".join(suspicious[:4])
            return (
                f"The model classified this URL as phishing because it shows suspicious indicators such as {shown}. "
                "These signals, including whether HTTPS is used, increase the risk that the URL is trying to disguise a malicious destination."
            )
        return (
            "The model classified this URL as phishing because it contains several unusual URL characteristics often linked to phishing, even if they are not individually above a fixed threshold."
        )

    if normal:
        shown = ", ".join(normal[:4])
        return (
            f"The model classified this URL as legitimate because it shows normal indicators such as {shown}. "
            "The URL structure, including its HTTPS status, is consistent with a regular website and does not display the most common phishing patterns."
        )

    return (
        "The model classified this URL as legitimate because the available URL features do not strongly match the known phishing patterns used during training."
    )


def generate_summary(features: Sequence[int], prediction: str, confidence: float | None) -> dict:
    if len(features) != 48:
        return {
            "result": prediction,
            "confidence": confidence,
            "brief": "The explanation service could not analyze the provided feature set.",
            "features": [],
            "why_phishing": "",
            "why_legitimate": "",
            "overall": {},
        }

    feature_rows = [_build_feature_row(i, int(features[i])) for i in range(len(features))]
    suspicious, normal, model_evaluated, important = _summarize_indicators(feature_rows)

    top_suspicious = suspicious[:3]
    top_normal = normal[:3]
    result_label = "Phishing" if "Phishing" in prediction else "Legitimate"

    brief = (
        f"The model returned {result_label} based on the URL feature values extracted from the current site. "
        "It compares these values against the heuristics and the learned patterns of the trained classifier."
    )
    if result_label == "Phishing":
        brief = (
            "The URL has several suspicious characteristics that match phishing behavior. "
            "These features increase the chance that the site is trying to disguise a malicious destination."
        )
    else:
        brief = (
            "The URL contains mostly normal values for the extracted features. "
            "The model did not find enough phishing-like signals to label this site as malicious."
        )

    why_phishing = (
        "The prediction leans toward phishing because the listed suspicious indicators are above their known thresholds or show known risky patterns. "
        "These include URL length, symbol usage, HTTPS absence, and the URL structure."
    )
    why_legitimate = (
        "The prediction leans toward legitimate because several values are within normal ranges and common phishing markers are absent. "
        "This includes moderate URL length, low dash usage, and the absence of obfuscation symbols."
    )

    if not suspicious:
        why_phishing = "There are no clearly suspicious URL features detected in the extracted values."
    if not normal:
        why_legitimate = "There are no clearly normal URL features detected based on the current threshold rules."

    overall = {
        "suspicious_count": len(suspicious),
        "normal_count": len(normal),
        "model_evaluated_count": len(model_evaluated),
        "most_important_suspicious": top_suspicious,
        "most_important_legitimate": top_normal,
        "final_reason": (
            "The model prediction is based on the combined feature vector passed to the classifier, "
            "with the highest-confidence class selected as the final label."
        ),
    }

    return {
        "result": prediction,
        "confidence": confidence,
        "brief": brief,
        "features": feature_rows,
        "why_phishing": why_phishing,
        "why_legitimate": why_legitimate,
        "overall": overall,
    }
