import asyncio
import gc
import logging
import time
import aiohttp
import socket
import pandas as pd
from bs4 import BeautifulSoup, FeatureNotFound, XMLParsedAsHTMLWarning
import warnings
from playwright.async_api import async_playwright, Error as PlaywrightError
import re
import os
import faulthandler
import json
from openai import AsyncOpenAI
import random
from enum import Enum, auto
from typing import Optional
from urllib.parse import urljoin, urlparse
import cloudscraper
import cloudscraper.exceptions as cf_exc
from requests import Response as RequestsResponse
from requests.exceptions import ConnectTimeout, ReadTimeout

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

def _silence_playwright_noise(loop, context):
    """Suppress noisy Playwright background-future warnings we cannot handle."""
    exc = context.get("exception")
    msg = context.get("message", "")
    _SILENT_EXC_TYPES = ("TargetClosedError",)
    _SILENT_MSG_FRAGMENTS = (
        "TargetClosedError",
        "Target page",
        "ERR_ABORTED",
        "frame was detached",
        "net::",
    )
    if exc is not None and (
        any(t in type(exc).__name__ for t in _SILENT_EXC_TYPES)
        or isinstance(exc, asyncio.CancelledError)
        or any(f in str(exc) for f in _SILENT_MSG_FRAGMENTS)
    ):
        return  # silently ignore
    if any(f in msg for f in _SILENT_MSG_FRAGMENTS):
        return  # silently ignore
    loop.default_exception_handler(context)


# Configuration
INPUT_FILE = "sites_to_check.xlsx"
OUTPUT_FILE = "leads_result.xlsx"

# Emails to always ignore (e.g., github support, wix, sentry, example.com)
SPAM_EMAILS = ["github.com", "sentry.io", "wixpress.com", "example.com", "yoursite.com", "domain.com", "email.com"]
IGNORE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")

# Email priority tiers
TIER_1_EMAILS = [
    "advertising@", "ad@", "business@", "partnership@", "marketing@", "sales@", "ceo@", "enquiry@", "enquiries@"
]
TIER_2_EMAILS = [
    "info@", "office@", "hello@", "contact@"
]

FORCED_PATHS = [
    "/contact", "/contact-us", "/about", "/about-us",
    "/advertise", "/advertising", "/partnership", "/partners",
    "/team", "/our-team", "/press", "/media-kit",
    "/reach-us", "/get-in-touch", "/work-with-us",
]

# Configure OpenAI (uses OPENAI_API_KEY environment variable by default)
# For local LLMs (like Ollama), set OPENAI_BASE_URL to "http://localhost:11434/v1"
client = AsyncOpenAI(
    base_url=os.environ.get("OPENAI_BASE_URL") or "http://localhost:11434/v1",
    api_key="ollama"
)

def normalize_url(domain: str) -> str:
    """Adds https:// if missing and cleans up whitespace."""
    domain = str(domain).strip()
    if not domain.startswith("http://") and not domain.startswith("https://"):
        return f"https://{domain}"
    return domain

def load_domains(file_path: str) -> list[str]:
    """Reads domains from Excel, normalizes them, and removes duplicates."""
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return []
    
    try:
        df = pd.read_excel(file_path)
        # Assuming domains are in the first column if no 'URL' column is specified
        column_name = "URL" if "URL" in df.columns else df.columns[0]
        
        # Remove empty rows
        df = df.dropna(subset=[column_name])
        
        # Normalize URLs
        df["Normalized_URL"] = df[column_name].apply(normalize_url)
        
        # Deduplicate
        unique_urls = df["Normalized_URL"].drop_duplicates().tolist()
        print(f"Loaded {len(unique_urls)} unique domains from {file_path}.")
        return unique_urls
    except Exception as e:
        print(f"Failed to read {file_path}: {e}")
        return []

def save_results(results: list[dict], file_path: str):
    """Saves the scraped results to an Excel file."""
    if not results:
        print("No results to save.")
        return
        
    df = pd.DataFrame(results)
    
    # Reorder columns to match expected output
    expected_columns = ["Site URL", "Email", "Thematic"]
    for col in expected_columns:
        if col not in df.columns:
            df[col] = ""  # Add empty column if missing
            
    df = df[expected_columns]
    
    try:
        df.to_excel(file_path, index=False)
        print(f"Results successfully saved to {file_path}")
    except Exception as e:
        print(f"Failed to save results to {file_path}: {e}")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

# ---------------------------------------------------------------------------
# Cloudflare Bypasser - ResponseStatus, ScraperError, CloudflareBypasser
# ---------------------------------------------------------------------------

# HTML / header markers that indicate a Cloudflare challenge or captcha page.
_CF_HTML_MARKERS: tuple[str, ...] = (
    "cf-challenge",
    "cf_chl_opt",
    "g-recaptcha",
    "h-captcha",
    "turnstile",
    "cf-please-wait",
    "jschl_vc",
    "chk_jschl",
    "Ray ID",
)
_CF_HEADER_MARKERS: tuple[str, ...] = ("cf-mitigated", "cf-chl-bypass")


class ResponseStatus(Enum):
    """Interpreted state of an HTTP response from the target site."""
    SUCCESS = auto()  # 200 OK with valid content
    CAPTCHA = auto()  # Cloudflare / hCaptcha / Turnstile challenge
    BANNED = auto()  # Hard 403 IP block (no captcha present)
    RATE_LIMITED = auto()  # 429 Too Many Requests
    UNKNOWN = auto()  # Any other non-success state


class ScraperError(Exception):
    """Raised when all CloudflareBypasser retry attempts are exhausted."""


class CloudflareBypasser:
    """
    Synchronous HTTP scraper that uses *cloudscraper* to bypass Cloudflare.

    Parameters
    ----------
    max_retries:
        Maximum fetch attempts before raising ``ScraperError``. Default: 5.
    base_backoff:
        Base for the exponential-backoff formula ``base_backoff ** attempt``.
        Default: 2  (-> 2 s, 4 s, 8 s, 16 s ...).
    browser:
        Browser fingerprint dict passed to ``cloudscraper.create_scraper``.
    extra_headers:
        Additional headers merged on top of cloudscraper's defaults.
    """

    def __init__(
        self,
        max_retries: int = 5,
        base_backoff: int = 2,
        browser: Optional[dict] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        self.max_retries  = max_retries
        self.base_backoff = base_backoff

        _browser = browser or {"browser": "chrome", "platform": "windows", "mobile": False}
        self._scraper: cloudscraper.CloudScraper = cloudscraper.create_scraper(
            browser=_browser,
            delay=5,
        )
        if extra_headers:
            self._scraper.headers.update(extra_headers)
        logger.debug("CloudflareBypasser ready (max_retries=%d).", max_retries)

    # ------------------------------------------------------------------
    def _get_status(self, response: RequestsResponse) -> ResponseStatus:
        """
        Classify *response* into a :class:`ResponseStatus`.

        Priority order
        --------------
        1. ``429``          -> RATE_LIMITED
        2. ``403`` + no CF  -> BANNED
        3. ``403`` + CF     -> CAPTCHA
        4. CF on any code   -> CAPTCHA
        5. 2xx              -> SUCCESS
        6. everything else  -> UNKNOWN
        """
        code = response.status_code

        if code == 429:
            logger.warning("Rate limited (HTTP 429).")
            return ResponseStatus.RATE_LIMITED

        has_cf_header = any(h in response.headers for h in _CF_HEADER_MARKERS)
        try:
            body = response.text
        except Exception:
            body = ""
        has_cf_body = any(m in body for m in _CF_HTML_MARKERS)
        is_captcha   = has_cf_header or has_cf_body

        if code == 403:
            if is_captcha:
                logger.warning("Cloudflare captcha/challenge detected (HTTP 403).")
                return ResponseStatus.CAPTCHA
            logger.warning("IP ban detected (HTTP 403, no captcha markers).")
            return ResponseStatus.BANNED

        if is_captcha:
            logger.warning("Cloudflare challenge detected (HTTP %d).", code)
            return ResponseStatus.CAPTCHA

        if 200 <= code < 300:
            return ResponseStatus.SUCCESS

        logger.warning("Unrecognised response state (HTTP %d).", code)
        return ResponseStatus.UNKNOWN

    # ------------------------------------------------------------------
    def _sleep(self, attempt: int) -> None:
        """Exponential backoff: sleeps ``base_backoff ** attempt`` seconds."""
        if attempt == 0:
            return
        delay = float(self.base_backoff ** attempt)
        logger.info("Backing off %.1fs before next attempt...", delay)
        time.sleep(delay)

    # ------------------------------------------------------------------
    def scrape(self, url: str) -> str:
        """
        Fetch *url* with Cloudflare bypass and exponential-backoff retries.

        Returns
        -------
        str
            Raw HTML of the successful response.

        Raises
        ------
        ScraperError
            When all retries fail.
        """
        last_error:  Optional[Exception]      = None
        last_status: Optional[ResponseStatus] = None

        for attempt in range(self.max_retries):
            self._sleep(attempt)
            logger.info("[%d/%d] cloudscraper -> %s", attempt + 1, self.max_retries, url)

            try:
                # Tuple timeout: (connect_timeout, read_timeout).
                # Short connect timeout so unreachable hosts fail fast and
                # fall through to Playwright without wasting minutes.
                response: RequestsResponse = self._scraper.get(
                    url, timeout=(10, 25)
                )
            except ConnectTimeout as exc:
                # TCP connection never established - retrying will not help.
                logger.warning(
                    "Connect timeout on attempt %d for %s - aborting cloudscraper.",
                    attempt + 1, url,
                )
                last_error = exc
                break  # skip remaining retries; let Playwright handle it
            except ReadTimeout as exc:
                # Connected but server was slow - worth retrying.
                logger.warning(
                    "Read timeout on attempt %d for %s - will retry.",
                    attempt + 1, url,
                )
                last_error = exc
                continue
            except cf_exc.CloudflareException as exc:
                logger.error("CloudflareException on attempt %d: %s", attempt + 1, exc)
                last_error = exc
                continue
            except Exception as exc:
                logger.error("Network error on attempt %d: %s", attempt + 1, exc)
                last_error = exc
                continue

            status = self._get_status(response)
            last_status = status

            if status == ResponseStatus.SUCCESS:
                logger.info("cloudscraper: success for %s.", url)
                return response.text

            if status == ResponseStatus.RATE_LIMITED:
                # Extra sleep on top of normal backoff - server asked us to slow down.
                extra = float(self.base_backoff ** (attempt + 1))
                logger.warning("Rate limited - extra sleep %.1fs.", extra)
                time.sleep(extra)
            elif status == ResponseStatus.BANNED:
                # Hard IP block - retrying the same IP will not help.
                logger.warning("IP ban on attempt %d - no proxy to rotate, aborting.", attempt + 1)
                break
            elif status == ResponseStatus.CAPTCHA:
                # Captcha requires human or solver - further retries are useless.
                logger.warning("Captcha on attempt %d - cannot solve, aborting.", attempt + 1)
                break
            else:
                logger.warning("Unknown state on attempt %d.", attempt + 1)

        raise ScraperError(
            f"All {self.max_retries} attempts failed for '{url}'. "
            f"Last status: {last_status}. Last error: {last_error}"
        )


# Module-level shared instance.
# max_retries=2 + base_backoff=1: worst-case thread life = ~27s
# (10s connect-fail x 1 + 1s sleep + 10s connect-fail x 1 = 21s)
# well inside safe_cloudscraper's 35s hard deadline.
_cf_bypasser = CloudflareBypasser(max_retries=2, base_backoff=1)

async def fetch_html_aiohttp(url: str, session: aiohttp.ClientSession) -> str:
    """Fetches HTML using fast aiohttp request."""
    try:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1"
        }
        async with session.get(url, headers=headers, timeout=45) as response:
            if response.status in [403, 429, 503]:
                return None
            return await response.text()
    except Exception:
        return None


def fetch_html_cloudscraper(url: str) -> Optional[str]:
    """
    Synchronous Cloudflare-bypass fetch using :class:`CloudflareBypasser`.

    This is intentionally synchronous - run it in a thread if needed inside
    an async context (``asyncio.to_thread``).
    """
    try:
        return _cf_bypasser.scrape(url)
    except ScraperError as exc:
        logger.warning("cloudscraper exhausted retries for %s: %s", url, exc)
        return None
    except Exception as exc:
        logger.error("Unexpected cloudscraper error for %s: %s", url, exc)
        return None

async def fetch_html_playwright(url: str, context) -> str:
    """Fetches HTML using Playwright with stealth and resource blocking."""
    page = await context.new_page()
    
    # Manual Stealth injection
    await page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    await page.add_init_script("window.chrome = { runtime: {} };")
    await page.add_init_script("Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});")
    
    # Block images/css using a proper async handler to avoid TargetClosedError
    async def block_resources(route):
        try:
            if route.request.resource_type in ["image", "stylesheet", "media", "font"]:
                await route.abort()
            else:
                await route.continue_()
        except Exception:
            pass  # Page may have been closed before the route resolved

    await page.route("**/*", block_resources)
    
    html = ""
    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=35000)
        # Brief wait for CF email-decoder JS - kept short to avoid stalling.
        await page.wait_for_timeout(1500)
        if response and response.status < 400:
            html = await page.content()
    except PlaywrightError as e:
        err_str = str(e)
        # ERR_ABORTED / frame detached are expected when we block resources
        # during a redirect - treat as empty result, not a crash.
        if "ERR_ABORTED" in err_str or "frame was detached" in err_str or "net::" in err_str:
            logger.debug("Playwright navigation aborted for %s (ignored): %s", url, err_str.splitlines()[0])
        else:
            logger.warning("Playwright error on %s: %s", url, err_str.splitlines()[0])
    except Exception as e:
        logger.warning("Playwright unexpected error on %s: %s", url, e)
    finally:
        try:
            await page.close()
        except Exception:
            pass  # page may already be closed
    return html


async def safe_cloudscraper(url: str, timeout: float = 35.0) -> Optional[str]:
    """
    Run ``fetch_html_cloudscraper`` in a thread-pool executor and enforce a
    hard asyncio-level deadline.

    ``asyncio.to_thread`` internally uses ``loop.run_in_executor``.  If the
    thread is blocked inside ``time.sleep`` (exponential backoff) it cannot
    be interrupted by ``asyncio.CancelledError``.  Wrapping with
    ``asyncio.wait_for`` makes the *asyncio* task time out and stop *waiting
    for* the thread result - the semaphore slot is freed immediately even if
    the background thread eventually finishes on its own.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(fetch_html_cloudscraper, url),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("cloudscraper thread timed out after %.0fs for %s.", timeout, url)
        return None
    except Exception as exc:
        logger.error("safe_cloudscraper unexpected error for %s: %s", url, exc)
        return None

async def safe_playwright(url: str, context, timeout: float = 35.0) -> Optional[str]:
    """Run Playwright fetch with a hard deadline so it cannot stall indefinitely."""
    try:
        return await asyncio.wait_for(
            fetch_html_playwright(url, context),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("Playwright timed out after %.0fs for %s.", timeout, url)
        return None
    except Exception as exc:
        logger.error("safe_playwright unexpected error for %s: %s", url, exc)
        return None

async def precheck_domain(
    base_url: str,
    session: aiohttp.ClientSession,
    dns_cache: dict[str, bool],
    head_cache: dict[str, int],
    cache_lock: asyncio.Lock,
) -> tuple[bool, Optional[int]]:
    """
    Fast DNS + HEAD precheck to skip obviously dead domains.
    Returns (ok, head_status). head_status may be None when not checked.
    """
    host = urlparse(base_url).hostname
    if not host:
        return False, None

    async with cache_lock:
        if host in dns_cache:
            dns_ok = dns_cache[host]
        else:
            dns_ok = None

    if dns_ok is None:
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=5)
            dns_ok = True
        except (asyncio.TimeoutError, socket.gaierror, OSError):
            dns_ok = False
        async with cache_lock:
            dns_cache[host] = dns_ok

    if not dns_ok:
        return False, None

    async with cache_lock:
        if base_url in head_cache:
            return True, head_cache[base_url]

    try:
        async with session.head(base_url, allow_redirects=True, timeout=10) as resp:
            status = resp.status
    except Exception:
        status = None

    async with cache_lock:
        head_cache[base_url] = status if status is not None else -1

    return True, status

async def scrape_domain(
    base_url: str,
    session: aiohttp.ClientSession,
    pw_context,
    semaphore: asyncio.Semaphore,
    dns_cache: dict[str, bool],
    head_cache: dict[str, int],
    cache_lock: asyncio.Lock,
) -> dict:
    """Main logic to scrape a single domain."""
    async with semaphore:
        logger.info("Scraping: %s", base_url)
        t_start = time.monotonic()
        timing = {}
        result = {
            "Site URL": base_url,
            "Email": "",
            "Thematic": ""
        }
        
        all_emails = set()
        best_content = ""

        # Fast DNS/HEAD precheck to skip dead domains early.
        ok, _head_status = await precheck_domain(
            base_url, session, dns_cache, head_cache, cache_lock
        )
        if not ok:
            logger.warning("Precheck failed (DNS/HEAD) for %s - skipping.", base_url)
            result["Thematic"] = "Offline / Unreachable"
            timing["total_s"] = round(time.monotonic() - t_start, 2)
            result["_timing"] = timing
            return result
        
        # Playwright Fallback Detectors
        cf_triggers = ["Just a moment...", "DDoS protection", "cf-browser-verification", "__cf_email__", "email-protection"]

        # STEP 1: Try aiohttp first ---
        fallback_triggered = False
        t0 = time.monotonic()
        homepage_html = await fetch_html_aiohttp(base_url, session)
        timing["aiohttp_s"] = round(time.monotonic() - t0, 2)

        # STEP 2: If aiohttp failed/blocked -> try cloudscraper ---
        # safe_cloudscraper wraps asyncio.to_thread with its own 35 s hard
        # deadline so the semaphore slot is never held by a sleeping thread.
        if homepage_html is None or any(trigger in homepage_html for trigger in cf_triggers):
            reason = "none" if homepage_html is None else "cf_triggers"
            logger.info("aiohttp fallback for %s (reason=%s) - trying cloudscraper...", base_url, reason)
            t0 = time.monotonic()
            homepage_html = await safe_cloudscraper(base_url)
            timing["cloudscraper_s"] = round(time.monotonic() - t0, 2)

        # STEP 3: If cloudscraper also failed -> try Playwright ---
        if homepage_html is None or any(trigger in homepage_html for trigger in cf_triggers):
            fallback_triggered = True
            reason = "none" if homepage_html is None else "cf_triggers"
            logger.info("cloudscraper fallback for %s (reason=%s) - using Playwright...", base_url, reason)
            t0 = time.monotonic()
            homepage_html = await safe_playwright(base_url, pw_context)
            timing["playwright_s"] = round(time.monotonic() - t0, 2)
            
        site_domain = urlparse(base_url).netloc.replace('www.', '')

        if homepage_html:
            t0 = time.monotonic()
            extracted = extract_page_content(homepage_html, base_url)
            timing["extract_s"] = round(time.monotonic() - t0, 2)
            all_emails.update(extracted["emails"])
            best_content = extracted["text_for_llm"]
            
            paths_to_scan = list(extracted.get("contact_links", set()))
            sitemap_urls = await get_sitemap_contact_urls(base_url, session)
            paths_to_scan.extend(sitemap_urls)
            for path in FORCED_PATHS:
                paths_to_scan.append(urljoin(base_url, path))
            paths_to_scan = list(dict.fromkeys(paths_to_scan))[:8]
        else:
            logger.warning("All fetch attempts failed for: %s", base_url)
            paths_to_scan = []
            timing["total_s"] = round(time.monotonic() - t_start, 2)
            result["_timing"] = timing

        # Hard budget for sub-page crawling to avoid long stalls per domain.
        subpage_scan_deadline = time.monotonic() + 75
        if fallback_triggered:
            # If homepage already required Playwright, keep sub-page crawl short.
            paths_to_scan = paths_to_scan[:2]

        # Early check on homepage emails
        current_best = get_best_email(all_emails, site_domain)
        if not (current_best and any(current_best.startswith(t1) for t1 in TIER_1_EMAILS)):
            for target_url in paths_to_scan:
                if time.monotonic() >= subpage_scan_deadline:
                    logger.info("Sub-page scan budget exhausted for %s.", base_url)
                    break
                if target_url == base_url or target_url == base_url + "/":
                    continue

                html = None
                if not fallback_triggered:
                    html = await fetch_html_aiohttp(target_url, session)
                    if html is None or any(trigger in html for trigger in cf_triggers):
                        logger.info("Sub-page aiohttp blocked (%s) - trying cloudscraper...", target_url)
                        html = await safe_cloudscraper(target_url)
                    if html is None or any(trigger in html for trigger in cf_triggers):
                        fallback_triggered = True
                        logger.info("Sub-page cloudscraper blocked (%s) - using Playwright...", target_url)
                        html = await safe_playwright(target_url, pw_context)
                else:
                    html = await safe_playwright(target_url, pw_context)

                if not html:
                    continue

                extracted_sub = extract_page_content(html, target_url)
                all_emails.update(extracted_sub["emails"])

                # Early exit if High Tier email found
                current_best = get_best_email(all_emails, site_domain)
                if current_best and any(current_best.startswith(t1) for t1 in TIER_1_EMAILS):
                    break

        if homepage_html:
            agency_emails = await extract_agency_emails(homepage_html, base_url, session, pw_context, fallback_triggered)
            if agency_emails:
                logger.info("Agency emails found for %s: %s", base_url, agency_emails)
                all_emails.update(agency_emails)

        # Finalize emails
        result["Email"] = get_best_email(all_emails, site_domain)
        
        # LLM email extraction removed; rely on direct extraction only.

        # Categorize
        if best_content:
            result["Thematic"] = await categorize_niche(best_content)
        else:
            result["Thematic"] = "Offline / Unreachable"

        timing["total_s"] = round(time.monotonic() - t_start, 2)
        result["_timing"] = timing
        logger.info("Finished %s - Email: %s, Niche: %s", base_url, result['Email'], result['Thematic'])
        return result

async def main():
    logger.info("Starting Smart Business & Contact Scraper...")
    loop = asyncio.get_event_loop()
    loop.set_exception_handler(_silence_playwright_noise)

    # 1. Load Data
    domains = load_domains(INPUT_FILE)
    if not domains:
        logger.warning("No domains to process. Exiting.")
        return

    results: list[dict] = []
    # Playwright can be less stable at high concurrency on Windows.
    concurrency_limit = max(1, int(os.environ.get("SCRAPER_CONCURRENCY", "2")))
    semaphore = asyncio.Semaphore(concurrency_limit)
    dns_cache: dict[str, bool] = {}
    head_cache: dict[str, int] = {}
    cache_lock = asyncio.Lock()
    timing_stats: list[tuple[str, float, dict]] = []

    # BATCH_SIZE controls how many domains share one browser_context.
    # A fresh context is created per batch (resets cookies/storage/memory)
    # while the underlying Chromium process stays alive the whole run.
    # Relaunching the browser every few sites was destabilizing Playwright.
    BATCH_SIZE = 10

    async def run_batch(
        batch: list[str],
        session: aiohttp.ClientSession,
        pw_context,
    ) -> list[dict]:
        """Run one batch of domains and return a list of result dicts."""

        DOMAIN_TIMEOUT = 90
        HEARTBEAT_EVERY = 30
        STALL_ABORT_AFTER = 180

        async def _domain_job(domain: str) -> tuple[str, Optional[dict], Optional[Exception]]:
            try:
                res = await asyncio.wait_for(
                    scrape_domain(
                        domain, session, pw_context, semaphore,
                        dns_cache, head_cache, cache_lock
                    ),
                    timeout=DOMAIN_TIMEOUT,
                )
                if isinstance(res, dict):
                    return domain, res, None
                return domain, None, RuntimeError(f"Unexpected task result type: {type(res).__name__}")
            except Exception as exc:
                return domain, None, exc

        task_to_domain = {
            asyncio.create_task(_domain_job(domain)): domain
            for domain in batch
        }
        pending = set(task_to_domain.keys())

        out: list[dict] = []
        completed = 0
        total = len(task_to_domain)
        last_progress_at = time.monotonic()

        while pending:
            done, pending = await asyncio.wait(
                pending,
                timeout=HEARTBEAT_EVERY,
                return_when=asyncio.FIRST_COMPLETED,
            )

            if not done:
                stalled_for = int(time.monotonic() - last_progress_at)
                pending_domains = [task_to_domain[t] for t in list(pending)[:3]]
                logger.warning(
                    "No batch progress for %ds. Pending: %d (e.g. %s)",
                    stalled_for,
                    len(pending),
                    ", ".join(pending_domains) if pending_domains else "n/a",
                )
                if stalled_for >= STALL_ABORT_AFTER:
                    logger.error("Batch stall detected. Cancelling %d pending task(s).", len(pending))
                    for t in pending:
                        t.cancel()
                    try:
                        await asyncio.wait_for(
                            asyncio.gather(*pending, return_exceptions=True),
                            timeout=5,
                        )
                    except Exception:
                        pass

                    for t in list(pending):
                        domain = task_to_domain[t]
                        out.append({
                            "Site URL": domain,
                            "Email": "",
                            "Thematic": "Error / TaskStalled",
                        })
                    pending.clear()
                continue

            last_progress_at = time.monotonic()
            for done_task in done:
                try:
                    domain, res, err = done_task.result()
                except Exception as err:
                    domain = task_to_domain.get(done_task, "UnknownDomain")
                    res = None

                if err is None and res is not None:
                    timing = res.pop("_timing", None)
                    if timing:
                        total_s = float(timing.get("total_s", 0.0))
                        timing_stats.append((domain, total_s, timing))
                    out.append(res)
                else:
                    exc_type = type(err).__name__ if err else "UnknownError"
                    exc_msg = (str(err) or repr(err)) if err else "No exception details"
                    logger.error("Task failed for %s - [%s] %s", domain, exc_type, exc_msg)
                    out.append({
                        "Site URL": domain,
                        "Email": "",
                        "Thematic": f"Error / {exc_type}",
                    })

                completed += 1
                logger.info("Batch progress: %d/%d completed.", completed, total)

        return out

    # 2. Process domains in batches
    # Strategy:
    #   * ONE browser process lives for the full run  (stable, no subprocess churn)
    #   * ONE aiohttp session lives for the full run  (connection pooling)
    #   * browser_context is recreated per batch      (clears page state / memory)
    #   * gc.collect() after each batch               (reclaims BS4/HTML objects)
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        connector = aiohttp.TCPConnector(
            limit=max(20, concurrency_limit * 6),
            limit_per_host=max(2, concurrency_limit),
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            batches = [
                domains[i : i + BATCH_SIZE]
                for i in range(0, len(domains), BATCH_SIZE)
            ]
            total_batches = len(batches)
            logger.info(
                "Processing %d domains in %d batch(es) of up to %d.",
                len(domains), total_batches, BATCH_SIZE,
            )

            for batch_num, batch in enumerate(batches, start=1):
                logger.info(
                    "--- Batch %d/%d (%d domains) ---",
                    batch_num, total_batches, len(batch),
                )

                # Fresh context per batch: resets cookies, localStorage, and
                # accumulated page memory without touching the browser process.
                pw_context = None
                try:
                    pw_context = await browser.new_context(ignore_https_errors=True)
                    # Guard against rare Playwright/network deadlocks:
                    # a batch cannot block forever.
                    batch_timeout = max(300, len(batch) * 210)
                    batch_results = await asyncio.wait_for(
                        run_batch(batch, session, pw_context),
                        timeout=batch_timeout,
                    )
                    results.extend(batch_results)

                except Exception as exc:
                    logger.error(
                        "Batch %d crashed: %s - marking remaining as Error.",
                        batch_num, exc,
                    )
                    already_done = {r["Site URL"] for r in results}
                    for domain in batch:
                        if domain not in already_done:
                            results.append({
                                "Site URL": domain,
                                "Email": "",
                                "Thematic": "Error / BatchCrash",
                            })
                finally:
                    if pw_context:
                        try:
                            await asyncio.wait_for(pw_context.close(), timeout=15)
                        except asyncio.TimeoutError:
                            logger.warning("Timed out while closing browser context for batch %d.", batch_num)
                        except Exception:
                            pass
                    gc.collect()

                # Save after every batch - results are never lost on crash.
                try:
                    save_results(results, OUTPUT_FILE)
                    logger.info(
                        "Batch %d/%d done. %d total results saved so far.",
                        batch_num, total_batches, len(results),
                    )
                except Exception as save_exc:
                    logger.error(
                        "Could not save after batch %d (file locked?): %s",
                        batch_num, save_exc,
                    )

        try:
            await asyncio.wait_for(browser.close(), timeout=20)
        except asyncio.TimeoutError:
            logger.warning("Timed out while closing Chromium browser.")

    # 3. Final save
    try:
        save_results(results, OUTPUT_FILE)
        logger.info("All done. %d results written to %s.", len(results), OUTPUT_FILE)
    except Exception as e:
        logger.error("Final save failed: %s", e)

    if timing_stats:
        slowest = sorted(timing_stats, key=lambda x: x[1], reverse=True)[:10]
        logger.info("Top slow domains (total_s):")
        for domain, total_s, timing in slowest:
            logger.info("  %s -> %.2fs (steps=%s)", domain, total_s, timing)

def decode_cf_email(encoded_str: str) -> str:
    """Decodes Cloudflare's email protection hashes."""
    try:
        r = int(encoded_str[:2], 16)
        email = "".join([chr(int(encoded_str[i:i+2], 16) ^ r) for i in range(2, len(encoded_str), 2)])
        return email
    except Exception:
        return ""

def extract_emails(text: str, soup=None) -> set:
    """Find email addresses quickly, with lightweight de-obfuscation."""
    # Avoid regex-heavy processing on very large pages.
    max_scan_chars = 400_000
    if len(text) > max_scan_chars:
        text = text[:max_scan_chars]

    clean_text = text
    # Fast token replacements before regex extraction.
    replacements = (
        ("[at]", "@"),
        ("(at)", "@"),
        ("{at}", "@"),
        (" at ", "@"),
        (" @ ", "@"),
        ("[dot]", "."),
        ("(dot)", "."),
        ("{dot}", "."),
        (" dot ", "."),
        (" . ", "."),
        ("\\u0040", "@"),
        ("&#64;", "@"),
        ("%40", "@"),
    )
    for old, new in replacements:
        clean_text = clean_text.replace(old, new)
        clean_text = clean_text.replace(old.upper(), new)

    email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    valid_emails = set()

    if soup:
        for tag in soup.find_all(attrs={"data-email": True}):
            valid_emails.update(extract_emails(tag["data-email"]))
        for tag in soup.find_all(attrs={"data-mail": True}):
            valid_emails.update(extract_emails(tag["data-mail"]))

    for match in email_pattern.finditer(clean_text):
        email = match.group(0)
        email = email.lower()
        if "%" in email:
            continue
        if any(spam in email for spam in SPAM_EMAILS):
            continue
        if email.endswith(IGNORE_EXTENSIONS):
            continue
        valid_emails.add(email)
        
    return valid_emails

def get_best_email(emails: set, site_domain: str = "") -> str:
    """Ranks and returns the best email from a set."""
    if not emails:
        return ""
        
    def is_domain_match(em: str) -> bool:
        if not site_domain or "@" not in em:
            return False
        return em.split("@")[1] == site_domain

    # Priority 1: Tier-1 prefix + domain matches the site
    for email in emails:
        if any(email.startswith(t1) for t1 in TIER_1_EMAILS) and is_domain_match(email):
            return email

    # Priority 2: Tier-1 prefix + any domain
    for email in emails:
        if any(email.startswith(t1) for t1 in TIER_1_EMAILS):
            return email

    # Priority 3: Tier-2 prefix + domain matches the site
    for email in emails:
        if any(email.startswith(t2) for t2 in TIER_2_EMAILS) and is_domain_match(email):
            return email

    # Priority 4: Tier-2 prefix + any domain
    for email in emails:
        if any(email.startswith(t2) for t2 in TIER_2_EMAILS):
            return email

    # Priority 5: any email + domain matches the site
    for email in emails:
        if is_domain_match(email):
            return email

    # Priority 6: any other email
    return list(emails)[0]

async def get_sitemap_contact_urls(base_url: str, session: aiohttp.ClientSession) -> list:
    urls = set()
    keywords = ["contact", "about", "advertising", "advertise", "partner"]
    for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
        sitemap_url = urljoin(base_url, sitemap_path)
        try:
            async with session.get(sitemap_url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    soup = BeautifulSoup(text, "xml")
                    for loc in soup.find_all("loc"):
                        if loc.text:
                            url = loc.text.strip()
                            url_lower = url.lower()
                            if any(kw in url_lower for kw in keywords):
                                urls.add(url)
        except Exception:
            pass
    return list(urls)


async def extract_agency_emails(html: str, base_url: str, session: aiohttp.ClientSession, pw_context, fallback_triggered: bool) -> set:
    try:
        agency_emails = set()
        soup = BeautifulSoup(html, "html.parser")
        base_domain = urlparse(base_url).netloc.replace('www.', '')
        
        agency_links = set()
        keywords = ["contact", "advertis", "partner", "agency", "media kit"]
        
        for a in soup.find_all("a", href=True):
            href = a.get("href", "").strip()
            link_text = a.get_text(strip=True).lower()
            if not href or href.startswith("tel:") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
                
            if any(kw in href.lower() or kw in link_text for kw in keywords):
                full_url = urljoin(base_url, href).split('#')[0]
                link_domain = urlparse(full_url).netloc.replace('www.', '')
                
                if link_domain and link_domain != base_domain:
                    agency_links.add(full_url)
                    
        agency_domains_seen = set()
        urls_to_scan = []
        for link in agency_links:
            link_domain = urlparse(link).netloc.replace('www.', '')
            if link_domain not in agency_domains_seen:
                agency_domains_seen.add(link_domain)
                urls_to_scan.append(link)
                if len(urls_to_scan) >= 1:
                    break
                    
        cf_triggers = ["Just a moment...", "DDoS protection", "cf-browser-verification", "__cf_email__", "email-protection"]
                    
        for url in urls_to_scan:
            page_html = None
            if not fallback_triggered:
                page_html = await fetch_html_aiohttp(url, session)
                if page_html is None or any(trigger in page_html for trigger in cf_triggers):
                    page_html = await safe_cloudscraper(url)
                if page_html is None or any(trigger in page_html for trigger in cf_triggers):
                    page_html = await safe_playwright(url, pw_context)
            else:
                page_html = await safe_playwright(url, pw_context)
                
            if page_html:
                extracted = extract_page_content(page_html, url)
                agency_emails.update(extracted["emails"])
                
        return agency_emails
    except Exception as e:
        logger.error("extract_agency_emails error: %s", e)
        return set()

def extract_jsonld_emails(soup) -> set:
    emails = set()
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            emails.update(extract_emails(json.dumps(data)))
        except Exception:
            pass
    return emails

def extract_page_content(html: str, base_url: str) -> dict:
    """Parses HTML and extracts relevant content for LLM and emails."""
    html_str = html.lstrip()
    looks_xml = html_str.startswith("<?xml") or "<urlset" in html_str[:200].lower()
    if looks_xml:
        try:
            soup = BeautifulSoup(html, "xml")
        except FeatureNotFound:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
                soup = BeautifulSoup(html, "html.parser")
    else:
        soup = BeautifulSoup(html, "html.parser")
    
    # Cloudflare email decoding
    for cf_email in soup.find_all("a", class_="__cf_email__"):
        encoded = cf_email.get("data-cfemail")
        if encoded:
            decoded = decode_cf_email(encoded)
            # Replace the a tag with plain email text
            cf_email.replace_with(decoded)
            
    # Extract metadata
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    meta_desc = ""
    meta_tag = soup.find("meta", attrs={"name": "description"})
    if meta_tag and meta_tag.get("content"):
        meta_desc = meta_tag["content"].strip()
        
    # Extract headings
    headings = " ".join([h.get_text(strip=True) for h in soup.find_all(['h1', 'h2', 'h3'])])
    
    # Extract contact links before removing all scripts/styles and texts
    contact_links = set()
    mailto_emails = set()
    keywords = ["contact", "about", "support", "advertising", "partnership"]
    
    base_domain = urlparse(base_url).netloc.replace('www.', '')
    # Simple check: base domain name (e.g., 'yugatech') without tld to allow www. & subdomains
    domain_core = base_domain.split('.')[-2] if '.' in base_domain else base_domain
    
    for a in soup.find_all("a", href=True):
        href = a.get("href", "").strip()
        if href.startswith("mailto:"):
            clean_email = href.replace("mailto:", "").split("?")[0].strip()
            if clean_email:
                mailto_emails.add(clean_email)
            continue
        if not href or href.startswith("tel:") or href.startswith("javascript:"):
            continue
            
        link_text = a.get_text(strip=True).lower()
        if any(kw in href.lower() or kw in link_text for kw in keywords):
            full_url = urljoin(base_url, href).split('#')[0]
            link_domain = urlparse(full_url).netloc
            # Check if domain_core is within the target link to allow redirects like www.
            if domain_core in link_domain:
                contact_links.add(full_url)
    
    # Extract visible text (clean up script/style)
    for script_or_style in soup(["script", "style", "noscript"]):
        script_or_style.decompose()
        
    text = soup.get_text(separator=" ", strip=True)
    emails = extract_emails(html, soup=soup)  # Extract from raw HTML to catch hidden ones too
    emails.update(extract_jsonld_emails(soup))
    emails.update(mailto_emails)  # Include explicit mailto links
    
    # Concatenate for LLM (max 2500 chars)
    combined_content = f"Title: {title}\nDescription: {meta_desc}\nHeadings: {headings}\nContent: {text}"
    truncated_content = combined_content[:2500]
    
    return {
        "text_for_llm": truncated_content,
        "emails": emails,
        "contact_links": contact_links
    }

# Phrases that indicate the LLM refused or couldn't classify
_LLM_REFUSAL_PHRASES = [
    "i'm sorry", "i am sorry", "i cannot", "i can't", "i apologize",
    "as an ai", "unable to", "not able to", "cannot classify",
    "please provide", "could you", "language model",
]

async def categorize_niche(content: str) -> str:
    if len(content) < 50:
        return "Unknown"

    system_prompt = (
        "You are a strict data classification AI. "
        "Your only task is to output the industry category of the website. "
        "You MUST reply with exactly 1 to 3 words. "
        "Never include conversational text, explanations, or introductory phrases."
    )
    user_prompt = (
        "Classify this website text into its core industry.\n"
        "Use one of these labels if it fits perfectly: News, E-commerce, SaaS, Law Firm, Healthcare, Marketing, Technology, Blog, Games, Casino.\n"
        "If none fit, provide a 1-3 word specific description (e.g., 'Username Generator', 'Video Hosting'). Do NOT reply with the word 'Other'.\n\n"
        f"Website text:\n{content[:1500]}\n\n"
        "Category:"
    )

    async def _call_llm() -> str:
        response = await client.chat.completions.create(
            model='llama3.2:3b',
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=40,
            temperature=0.0,
        )
        return (response.choices[0].message.content or "").strip()

    try:
        # Hard 45 s deadline - prevents a slow/hung Ollama from blocking the
        # entire scrape_domain coroutine (and therefore the semaphore slot).
        raw_reply = await asyncio.wait_for(_call_llm(), timeout=45)
    except asyncio.TimeoutError:
        logger.warning("LLM call timed out - returning 'Unknown'.")
        return "Unknown"
    except Exception as e:
        logger.error("LLM error: %s", e)
        return "Unknown"

    # Strip <think>...</think> from reasoning/thinking models (qwen3, deepseek-r1, etc.)
    cleaned_reply = re.sub(r"<think>.*?</think>", "", raw_reply, flags=re.DOTALL).strip()
    logger.info("LLM raw: %r | cleaned: %r", raw_reply[:150], cleaned_reply[:100])

    raw_lower = cleaned_reply.lower()
    if any(phrase in raw_lower for phrase in _LLM_REFUSAL_PHRASES):
        logger.debug("LLM refusal detected, defaulting to 'Other'. Raw: %s", cleaned_reply[:80])
        return "Other"

    # Clean up generic prefixes
    cleaned = cleaned_reply.replace('"', '').replace("'", "")
    if cleaned.lower().startswith("category:"):
        cleaned = cleaned[9:].strip()
    elif cleaned.lower().startswith("niche:"):
        cleaned = cleaned[6:].strip()

    cleaned_lower = cleaned.lower()
    for valid_niche in ["News", "E-commerce", "SaaS", "Law Firm", "Healthcare",
                        "Marketing", "Technology", "Blog", "Games", "Casino"]:
        if valid_niche.lower() in cleaned_lower:
            return valid_niche

    final_cat = cleaned.split("\n")[0][:35].strip()
    if not final_cat or final_cat.lower() == "other":
        return "Other"

    logger.debug("LLM custom category: '%s'", final_cat)
    return final_cat.title() if final_cat.islower() else final_cat

if __name__ == "__main__":
    enable_hang_dump = os.environ.get("SCRAPER_HANG_DUMP", "").strip() == "1"
    if enable_hang_dump:
        faulthandler.enable()
        faulthandler.dump_traceback_later(90, repeat=True)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception:
        # Print the full traceback so we can see exactly what crashed.
        logger.critical("Unhandled top-level exception:", exc_info=True)
    finally:
        if enable_hang_dump:
            faulthandler.cancel_dump_traceback_later()
