from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import tempfile
import ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from bs4.element import Tag
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


TARGET_URL = "https://cetonline.karnataka.gov.in/kea/pgcet2026"
STATE_FILE = Path(__file__).resolve().with_name("known_announcements.json")
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 25
REQUEST_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
DIAGNOSTICS_TIMEOUT = 8
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36 KEA-Monitor/1.0"
)


logger = logging.getLogger("kea_monitor")


DATE_PATTERNS = (
    re.compile(r"\b(\d{2}[-/]\d{2}[-/]\d{4})\b"),
    re.compile(r"\b(\d{4}-\d{2}-\d{2})\b"),
)


@dataclass(slots=True)
class Announcement:
    id: str
    title: str
    url: str | None
    date: str | None
    visible_text: str
    links: list[str]
    pdf_urls: list[str]
    parent_title: str | None
    hash: str


def setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        status=4,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
    )
    proxy_url = load_env("REQUESTS_PROXY")
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
        parsed_proxy = urlparse(proxy_url)
        logger.info(
            "Using proxy for outbound requests: %s://%s",
            parsed_proxy.scheme or "http",
            parsed_proxy.netloc or "configured-proxy",
        )
    return session


def is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def family_label(family: int) -> str:
    if family == socket.AF_INET:
        return "IPv4"
    if family == socket.AF_INET6:
        return "IPv6"
    return f"family={family}"


def summarize_proxy(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc or "unknown"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme or 'http'}://{host}"


def summarize_headers(headers: dict[str, str]) -> str:
    fields = ("User-Agent", "Accept", "Accept-Language", "Cache-Control", "Pragma")
    return ", ".join(f"{name}={headers.get(name)!r}" for name in fields if name in headers)


def summarize_cert(cert: dict[str, Any]) -> str:
    subject_parts = []
    for entry in cert.get("subject", []):
        for key, value in entry:
            subject_parts.append(f"{key}={value}")
    issuer_parts = []
    for entry in cert.get("issuer", []):
        for key, value in entry:
            issuer_parts.append(f"{key}={value}")
    san_entries = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    summary = [
        f"subject={'/'.join(subject_parts) if subject_parts else 'unknown'}",
        f"issuer={'/'.join(issuer_parts) if issuer_parts else 'unknown'}",
        f"notAfter={cert.get('notAfter', 'unknown')}",
    ]
    if san_entries:
        summary.append(f"san={', '.join(san_entries[:6])}")
    return ", ".join(summary)


def log_network_diagnostics(session: requests.Session, url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        logger.warning("Cannot run network diagnostics because the target host is missing")
        return

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    logger.info("Network diagnostics enabled for %s", url)
    logger.info("Configured timeouts: connect=%ss read=%ss diagnostics_probe=%ss", CONNECT_TIMEOUT, READ_TIMEOUT, DIAGNOSTICS_TIMEOUT)
    logger.info("Transport note: requests uses HTTP/1.1; response logging will show the negotiated HTTP version")
    logger.info("Request headers: %s", summarize_headers(session.headers))

    if session.proxies:
        logger.info("Direct socket probes below bypass the configured proxy and are for reference only")
        for scheme, proxy_url in session.proxies.items():
            logger.info("Proxy for %s: %s", scheme, summarize_proxy(proxy_url))
    else:
        logger.info("No outbound proxy configured")

    try:
        resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        logger.exception("DNS resolution failed for %s:%s: %s", host, port, exc)
        return

    seen_endpoints: set[tuple[int, tuple[Any, ...]]] = set()
    for family, _socktype, _proto, canonname, sockaddr in resolved:
        ip_address = sockaddr[0]
        logger.info(
            "DNS result: family=%s address=%s port=%s canonname=%s",
            family_label(family),
            ip_address,
            sockaddr[1],
            canonname or "-",
        )
        key = (family, sockaddr)
        if key in seen_endpoints:
            continue
        seen_endpoints.add(key)

        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(DIAGNOSTICS_TIMEOUT)
                logger.info(
                    "TCP probe start: family=%s address=%s port=%s timeout=%ss",
                    family_label(family),
                    ip_address,
                    sockaddr[1],
                    DIAGNOSTICS_TIMEOUT,
                )
                sock.connect(sockaddr)
                logger.info(
                    "TCP probe success: family=%s address=%s port=%s",
                    family_label(family),
                    ip_address,
                    sockaddr[1],
                )

                if parsed.scheme.lower() == "https":
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                        logger.info(
                            "TLS handshake success: family=%s address=%s tls_version=%s cipher=%s alpn=%s",
                            family_label(family),
                            ip_address,
                            tls_sock.version() or "unknown",
                            tls_sock.cipher(),
                            tls_sock.selected_alpn_protocol() or "none",
                        )
                        peer_cert = tls_sock.getpeercert() or {}
                        if peer_cert:
                            logger.info("TLS peer certificate: %s", summarize_cert(peer_cert))
        except OSError as exc:
            logger.warning(
                "Probe failed: family=%s address=%s port=%s error=%s",
                family_label(family),
                ip_address,
                sockaddr[1],
                exc,
            )


def log_http_response_details(response: requests.Response) -> None:
    http_version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(response.raw, "version", None), "unknown")
    logger.info(
        "HTTP response: status=%s reason=%s url=%s http_version=%s content_type=%s content_length=%s",
        response.status_code,
        response.reason,
        response.url,
        http_version,
        response.headers.get("Content-Type", "-"),
        response.headers.get("Content-Length", "-"),
    )
    if response.history:
        for index, hop in enumerate(response.history, start=1):
            logger.info(
                "Redirect hop %d: status=%s from=%s to=%s",
                index,
                hop.status_code,
                hop.url,
                hop.headers.get("Location", "-"),
            )
    logger.info("Final request headers: %s", summarize_headers(response.request.headers))


def describe_request_exception(exc: requests.RequestException) -> str:
    chain: list[str] = []
    current: BaseException | None = exc
    for _ in range(4):
        if current is None:
            break
        chain.append(f"{type(current).__name__}: {current}")
        current = current.__cause__ or current.__context__
    return " -> ".join(chain)


def fetch_page(session: requests.Session, url: str, *, diagnostics_enabled: bool = False) -> str | None:
    try:
        response = session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        response.encoding = response.encoding or "utf-8"
        log_http_response_details(response)
        return response.text
    except requests.ConnectTimeout as exc:
        logger.exception("Connect timeout while fetching %s: %s", url, describe_request_exception(exc))
        if diagnostics_enabled:
            log_network_diagnostics(session, url)
        return None
    except requests.ReadTimeout as exc:
        logger.exception("Read timeout while fetching %s: %s", url, describe_request_exception(exc))
        if diagnostics_enabled:
            log_network_diagnostics(session, url)
        return None
    except requests.SSLError as exc:
        logger.exception("TLS/SSL error while fetching %s: %s", url, describe_request_exception(exc))
        if diagnostics_enabled:
            log_network_diagnostics(session, url)
        return None
    except requests.RequestException as exc:
        logger.exception("Failed to fetch page: %s", describe_request_exception(exc))
        if diagnostics_enabled:
            log_network_diagnostics(session, url)
        return None


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def strip_tracking(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


def absolute_url(base_url: str, href: str | None) -> str | None:
    if not href:
        return None
    href = href.strip()
    if not href or href.startswith("#") or href.lower().startswith("javascript:"):
        return None
    return strip_tracking(urljoin(base_url, href))


def is_pdf_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith(".pdf") or ".pdf" in path


def extract_links(node: Tag, base_url: str) -> list[str]:
    seen: set[str] = set()
    links: list[str] = []
    for anchor in node.find_all("a", href=True):
        url = absolute_url(base_url, anchor.get("href"))
        if url and url not in seen:
            seen.add(url)
            links.append(url)
    return links


def extract_visible_text(node: Tag) -> str:
    return normalize_whitespace(node.get_text(" ", strip=True))


def extract_date(text: str) -> str | None:
    for pattern in DATE_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def make_identity_key(title: str, url: str | None, parent_title: str | None, date: str | None) -> str:
    parts = []
    if url:
        parts.append(f"url:{url}")
    else:
        parts.append(f"title:{normalize_whitespace(title).lower()}")
        if parent_title:
            parts.append(f"parent:{normalize_whitespace(parent_title).lower()}")
        if date:
            parts.append(f"date:{date}")
    return hashlib.sha256("||".join(parts).encode("utf-8")).hexdigest()


def make_content_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def first_meaningful_heading(node: Tag) -> str | None:
    heading = node.find(
        lambda tag: isinstance(tag, Tag)
        and tag.name in {"h1", "h2", "h3", "h4", "h5", "h6"}
        and normalize_whitespace(tag.get_text(" ", strip=True))
    )
    if heading is not None:
        return normalize_whitespace(heading.get_text(" ", strip=True))
    return None


def is_announcement_block(node: Tag) -> bool:
    if node.name in {"a", "h1", "h2", "h3", "h4", "h5", "h6"}:
        return True

    classes = " ".join(node.get("class", [])).lower()
    class_hints = (
        "card",
        "item",
        "notice",
        "announcement",
        "alert",
        "news",
        "bulletin",
        "list-group-item",
        "post",
        "content",
    )
    if any(hint in classes for hint in class_hints):
        return True

    direct_links = [child for child in node.find_all("a", recursive=False)]
    direct_headings = [
        child
        for child in node.find_all(
            lambda tag: isinstance(tag, Tag)
            and tag.name in {"h1", "h2", "h3", "h4", "h5", "h6"},
            recursive=False,
        )
    ]
    if direct_links or direct_headings:
        return True

    text = extract_visible_text(node)
    if text and extract_date(text):
        return True

    return False


def has_direct_announcement_children(node: Tag) -> bool:
    return any(
        isinstance(child, Tag) and child.name in {"a", "h1", "h2", "h3", "h4", "h5", "h6"}
        for child in node.children
    )


def build_announcement(
    node: Tag,
    base_url: str,
    parent_title: str | None,
) -> Announcement | None:
    visible_text = extract_visible_text(node)
    if not visible_text:
        return None

    heading = first_meaningful_heading(node)
    title = heading or visible_text

    links = extract_links(node, base_url)
    pdf_urls = [url for url in links if is_pdf_url(url)]
    url = links[0] if links else None
    date = extract_date(visible_text) or extract_date(title)

    identity = make_identity_key(title, url, parent_title, date)
    content_hash = make_content_hash(
        {
            "title": title,
            "url": url,
            "date": date,
            "visible_text": visible_text,
            "links": links,
            "pdf_urls": pdf_urls,
            "parent_title": parent_title,
        }
    )

    return Announcement(
        id=identity,
        title=title,
        url=url,
        date=date,
        visible_text=visible_text,
        links=links,
        pdf_urls=pdf_urls,
        parent_title=parent_title,
        hash=content_hash,
    )


def walk_announcement_blocks(
    node: Tag,
    base_url: str,
    parent_title: str | None = None,
    *,
    record_self: bool = True,
) -> list[Announcement]:
    announcements: list[Announcement] = []

    if record_self and is_announcement_block(node):
        should_record_self = node.name in {"a", "h1", "h2", "h3", "h4", "h5", "h6"} or not has_direct_announcement_children(node)
    else:
        should_record_self = False

    if should_record_self:
        announcement = build_announcement(node, base_url, parent_title)
        if announcement is not None:
            announcements.append(announcement)
            parent_title = announcement.title

    direct_children = [child for child in node.children if isinstance(child, Tag)]
    for child in direct_children:
        if child.name == "a" and not child.find_all(["a", "h1", "h2", "h3", "h4", "h5", "h6"]):
            announcement = build_announcement(child, base_url, parent_title)
            if announcement is not None:
                announcements.append(announcement)
            continue

        if is_announcement_block(child):
            announcements.extend(walk_announcement_blocks(child, base_url, parent_title))
            continue

        if child.find(lambda tag: isinstance(tag, Tag) and tag.name in {"a", "h1", "h2", "h3", "h4", "h5", "h6"}):
            announcements.extend(walk_announcement_blocks(child, base_url, parent_title))

    return deduplicate_announcements(announcements)


def deduplicate_announcements(items: Iterable[Announcement]) -> list[Announcement]:
    ordered: list[Announcement] = []
    seen: set[str] = set()
    for item in items:
        if item.id in seen:
            continue
        seen.add(item.id)
        ordered.append(item)
    return ordered


def find_announcement_container(soup: BeautifulSoup) -> Tag | None:
    candidates = soup.select("div.card-deck.shadow")
    if not candidates:
        candidates = soup.select("div.card-deck") + soup.select("div.shadow")
    if not candidates:
        return None

    def score(node: Tag) -> tuple[int, int]:
        return (len(node.find_all("a")), len(node.find_all(True)))

    return max(candidates, key=score)


def inspect_structure(container: Tag) -> None:
    direct_children = [child for child in container.children if isinstance(child, Tag)]
    direct_with_links = sum(1 for child in direct_children if child.find("a"))
    nested_headings = sum(
        1
        for child in direct_children
        if child.find(lambda tag: isinstance(tag, Tag) and tag.name in {"h1", "h2", "h3", "h4", "h5", "h6"})
    )
    logger.info(
        "Announcement container located: <%s class=%s>, direct_children=%d, direct_children_with_links=%d, direct_children_with_headings=%d",
        container.name,
        " ".join(container.get("class", [])),
        len(direct_children),
        direct_with_links,
        nested_headings,
    )

    sample = []
    for child in direct_children[:5]:
        tag_name = child.name
        text = normalize_whitespace(child.get_text(" ", strip=True))[:90]
        sample.append(f"{tag_name}:{text}")
    if sample:
        logger.info("Container sample: %s", " | ".join(sample))


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "version": 1,
            "source_url": TARGET_URL,
            "startup_notified": False,
            "last_checked": None,
            "announcements": [],
        }

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            return {
                "version": 1,
                "source_url": TARGET_URL,
                "startup_notified": bool(data),
                "last_checked": None,
                "announcements": data,
            }
        if isinstance(data, dict):
            data.setdefault("version", 1)
            data.setdefault("source_url", TARGET_URL)
            data.setdefault("startup_notified", False)
            data.setdefault("last_checked", None)
            data.setdefault("announcements", [])
            return data
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Unable to read existing state file, starting fresh: %s", exc)

    return {
        "version": 1,
        "source_url": TARGET_URL,
        "startup_notified": False,
        "last_checked": None,
        "announcements": [],
    }


def save_state(path: Path, state: dict[str, Any]) -> None:
    payload = json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent, suffix=".tmp") as handle:
        handle.write(payload)
        temp_name = handle.name
    Path(temp_name).replace(path)


def current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def truncate(text: str, limit: int = 240) -> str:
    text = normalize_whitespace(text)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def load_env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def send_telegram_message(session: requests.Session, text: str) -> bool:
    bot_token = load_env("BOT_TOKEN")
    chat_id = load_env("CHAT_ID")

    if not bot_token or not chat_id:
        logger.warning("BOT_TOKEN or CHAT_ID not set, skipping Telegram notification")
        return False

    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }

    try:
        response = session.post(api_url, data=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        body = response.json()
        if not body.get("ok", False):
            logger.warning("Telegram API returned a non-ok response: %s", body)
            return False
        return True
    except (requests.RequestException, ValueError) as exc:
        logger.exception("Failed to send Telegram message: %s", exc)
        return False


def format_notification(announcement: Announcement) -> str:
    parts = [
        "🚨 KEA PGCET UPDATE",
        "",
        f"Title: {truncate(announcement.title, 320)}",
    ]
    if announcement.url:
        parts.append(f"Link: {truncate(announcement.url, 700)}")
    elif announcement.links:
        parts.append(f"Link: {truncate(announcement.links[0], 700)}")
    else:
        parts.append("Link: unavailable")

    if announcement.pdf_urls:
        parts.append(f"PDF: {truncate(announcement.pdf_urls[0], 700)}")
        if len(announcement.pdf_urls) > 1:
            extra = "; ".join(truncate(url, 200) for url in announcement.pdf_urls[1:3])
            parts.append(f"Other PDFs: {extra}")

    if announcement.date:
        parts.append(f"Date: {announcement.date}")

    parts.append(f"Detected: {current_timestamp()}")
    return "\n".join(parts)


def format_startup_message() -> str:
    return "\n".join(
        [
            "✅ KEA Monitor Running",
            "",
            "Monitoring:",
            TARGET_URL,
        ]
    )


def normalize_announcements(items: list[Announcement]) -> list[dict[str, Any]]:
    return [asdict(item) for item in items]


def compare_announcements(
    previous: list[dict[str, Any]],
    current: list[Announcement],
) -> tuple[list[Announcement], list[Announcement], list[Announcement]]:
    previous_by_id = {item.get("id"): item for item in previous if item.get("id")}
    current_by_id = {item.id: item for item in current}

    new_items = []
    modified_items = []
    removed_items = []

    for item in current:
        previous_item = previous_by_id.get(item.id)
        if previous_item is None:
            new_items.append(item)
        elif previous_item.get("hash") != item.hash:
            modified_items.append(item)

    for previous_id, previous_item in previous_by_id.items():
        if previous_id not in current_by_id:
            removed_items.append(
                Announcement(
                    id=previous_item.get("id", previous_id),
                    title=previous_item.get("title", ""),
                    url=previous_item.get("url"),
                    date=previous_item.get("date"),
                    visible_text=previous_item.get("visible_text", ""),
                    links=list(previous_item.get("links") or []),
                    pdf_urls=list(previous_item.get("pdf_urls") or []),
                    parent_title=previous_item.get("parent_title"),
                    hash=previous_item.get("hash", ""),
                )
            )

    return new_items, modified_items, removed_items


def run_git_command(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )


def commit_and_push_if_needed(repo_root: Path, state_file: Path) -> None:
    try:
        status = run_git_command(["status", "--porcelain", "--", state_file.name], repo_root)
        if not status.stdout.strip():
            logger.info("No state changes to commit")
            return

        try:
            run_git_command(["config", "user.name", "kea-monitor-bot"], repo_root)
            run_git_command(["config", "user.email", "kea-monitor-bot@users.noreply.github.com"], repo_root)
        except subprocess.CalledProcessError:
            logger.warning("Unable to configure git identity, continuing with existing config")

        run_git_command(["add", state_file.name], repo_root)
        run_git_command(["commit", "-m", "chore: update KEA PGCET monitor state"], repo_root)

        branch = os.environ.get("GITHUB_REF_NAME")
        if not branch:
            branch_result = run_git_command(["branch", "--show-current"], repo_root)
            branch = branch_result.stdout.strip() or "main"

        try:
            run_git_command(["push", "origin", f"HEAD:{branch}"], repo_root)
            logger.info("Committed and pushed state updates to %s", branch)
        except subprocess.CalledProcessError as exc:
            logger.exception("Commit succeeded but push failed: %s", exc)
    except subprocess.CalledProcessError as exc:
        logger.exception("Git operation failed: %s", exc)


def bootstrap_or_update_state(
    state: dict[str, Any],
    current_announcements: list[Announcement],
    session: requests.Session,
) -> dict[str, Any]:
    previous_announcements = list(state.get("announcements") or [])
    startup_notified = bool(state.get("startup_notified"))
    new_items, modified_items, _removed_items = compare_announcements(previous_announcements, current_announcements)

    if not startup_notified:
        logger.info("First successful run detected; sending startup notification")
        if send_telegram_message(session, format_startup_message()):
            state["startup_notified"] = True
        else:
            logger.warning("Startup notification could not be delivered")

    if startup_notified and (new_items or modified_items):
        logger.info(
            "Detected changes: new=%d modified=%d",
            len(new_items),
            len(modified_items),
        )
        for announcement in new_items + modified_items:
            message = format_notification(announcement)
            send_telegram_message(session, message)
    elif startup_notified:
        logger.info("No announcement changes detected")

    state["source_url"] = TARGET_URL
    state["last_checked"] = current_timestamp()
    state["announcements"] = normalize_announcements(current_announcements)
    if not state.get("startup_notified"):
        state["startup_notified"] = startup_notified

    return state


def main() -> int:
    setup_logging()
    logger.info("Starting KEA PGCET monitor")

    repo_root = Path(__file__).resolve().parent
    state = load_state(STATE_FILE)
    session = create_session()
    diagnostics_enabled = is_truthy(load_env("NETWORK_DIAGNOSTICS"))

    if diagnostics_enabled:
        log_network_diagnostics(session, TARGET_URL)

    html = fetch_page(session, TARGET_URL, diagnostics_enabled=False)
    if not html:
        logger.warning("Skipping update because the target page could not be fetched")
        return 0

    soup = BeautifulSoup(html, "html.parser")
    container = find_announcement_container(soup)
    if container is None:
        logger.warning("Announcement container not found on the page")
        return 0

    inspect_structure(container)

    current_announcements = walk_announcement_blocks(container, TARGET_URL, record_self=False)
    logger.info("Extracted %d announcement records", len(current_announcements))

    updated_state = bootstrap_or_update_state(state, current_announcements, session)
    save_state(STATE_FILE, updated_state)
    commit_and_push_if_needed(repo_root, STATE_FILE)

    logger.info("Monitor run completed successfully")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        raise SystemExit(130)
