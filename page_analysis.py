from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

MAX_RESPONSE_BYTES = 2_000_000
REQUEST_TIMEOUT = (3.05, 6)
MAX_REDIRECTS = 5

SENSITIVE_WORDS = (
    "login", "verify", "password", "account", "bank", "secure",
    "wallet", "payment", "invoice", "urgent", "confirm", "signin",
)
BRAND_NAMES = (
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "whatsapp", "netflix", "github",
)


def _is_public_hostname(hostname: str) -> bool:
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError("The domain could not be resolved.") from error

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            return False
    return True


def validate_public_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("A valid public HTTP(S) URL is required.")

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public HTTP(S) URLs can be analyzed.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing user credentials are not allowed.")
    if not _is_public_hostname(parsed.hostname):
        raise ValueError("Private, loopback, and internal network addresses are not allowed.")
    return value


def _read_html(response: requests.Response) -> str:
    content_type = response.headers.get("Content-Type", "").lower()
    if content_type and "html" not in content_type and "text/" not in content_type:
        raise ValueError("The target did not return an HTML page.")

    data = bytearray()
    for chunk in response.iter_content(chunk_size=32_768):
        data.extend(chunk)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("The target page is too large to analyze.")
    return bytes(data).decode(response.encoding or "utf-8", errors="replace")


def fetch_public_html(url: str) -> tuple[str, str, int]:
    current_url = validate_public_url(url)
    session = requests.Session()
    session.headers.update({"User-Agent": "PhishingDetector/1.0 page analyzer"})

    for redirect_count in range(MAX_REDIRECTS + 1):
        response = session.get(
            current_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location or redirect_count == MAX_REDIRECTS:
                raise ValueError("The redirect chain could not be safely followed.")
            current_url = validate_public_url(urljoin(current_url, location))
            continue

        response.raise_for_status()
        try:
            return current_url, _read_html(response), redirect_count
        finally:
            response.close()

    raise ValueError("The page could not be fetched safely.")


def extract_page_features(url: str, html: str, redirect_count: int) -> tuple[dict, dict]:
    soup = BeautifulSoup(html, "html.parser")
    for element in soup(["script", "style", "noscript", "template"]):
        element.decompose()

    visible_text = soup.get_text(" ", strip=True).lower()
    links = soup.find_all("a", href=True)
    resources = soup.find_all(["script", "img", "iframe"], src=True) + soup.find_all("link", href=True)
    external_resources = []
    for resource in resources:
        try:
            resource_url = resource.get("src") or resource.get("href")
            if resource_url and urlparse(urljoin(url, resource_url)).hostname != urlparse(url).hostname:
                external_resources.append(resource)
        except ValueError:
            continue
    external_links = []
    for link in links:
        try:
            if urlparse(urljoin(url, link["href"])).hostname != urlparse(url).hostname:
                external_links.append(link)
        except ValueError:
            continue

    forms = soup.find_all("form")
    form_actions = [urljoin(url, form.get("action") or url) for form in forms]
    external_forms = [action for action in form_actions if urlparse(action).hostname != urlparse(url).hostname]
    external_favicon = 0
    for icon in soup.find_all(
        "link",
        rel=lambda value: value and (
            "icon" in value.lower()
            if isinstance(value, str)
            else any("icon" in item.lower() for item in value)
        ),
    ):
        try:
            if urlparse(urljoin(url, icon.get("href", ""))).hostname != urlparse(url).hostname:
                external_favicon = 1
                break
        except ValueError:
            continue
    password_fields = soup.select('input[type="password"]')
    login_forms = [
        form for form in forms
        if form.select_one('input[type="password"]')
        or any(word in form.get_text(" ", strip=True).lower() for word in ("login", "sign in", "password"))
    ]
    metadata = {
        "title": soup.title.get_text(" ", strip=True) if soup.title else "",
        "visible_text_length": len(visible_text),
        "link_count": len(links),
        "form_count": len(forms),
        "password_field_count": len(password_fields),
        "login_form_count": len(login_forms),
        "external_link_count": len(external_links),
        "iframe_count": len(soup.find_all(["iframe", "frame"])),
        "redirect_count": redirect_count,
        "meta_description": (soup.find("meta", attrs={"name": "description"}) or {}).get("content", ""),
    }
    page_features = {
        "sensitive_words": sum(word in visible_text for word in SENSITIVE_WORDS),
        "embedded_brand": int(any(brand in visible_text for brand in BRAND_NAMES)),
        "external_link_ratio": len(external_links) / len(links) if links else 0,
        "external_resource_ratio": len(external_resources) / len(resources) if resources else 0,
        "external_favicon": external_favicon,
        "insecure_forms": int(any(urlparse(action).scheme != "https" for action in form_actions)),
        "relative_form_action": int(any(not urlparse(action).scheme for action in form_actions)),
        "external_form_action": int(bool(external_forms)),
        "abnormal_form_action": int(bool(external_forms)),
        "null_self_redirect": sum(not link.get("href") or link.get("href") == "#" for link in links),
        "iframe": int(bool(metadata["iframe_count"])),
        "missing_title": int(not metadata["title"]),
        "images_only_form": int(any(form.find("img") and not form.find_all(["input", "button", "textarea", "select"]) for form in forms)),
        "meta_script_link_ratio": len(external_resources) / len(resources) if resources else 0,
    }
    return page_features, metadata


def analyze_public_url(url: str) -> tuple[str, dict, dict]:
    final_url, html, redirect_count = fetch_public_html(url)
    page_features, metadata = extract_page_features(final_url, html, redirect_count)
    return final_url, page_features, metadata
