"""
Advanced Telegram file-downloader bot with stream auditing, JWT extraction,
HLS support, HTML parsing, and concurrent chunked downloads.

Flow per link a user sends:
  1. Validate the URL (SSRF guard + redirect resolution).
  2. Extract direct URL (JWT decode, API scraping, HTML parsing, HLS detection).
  3. Download to local disk (streamed, throttled progress, chunked for large files).
  4. Upload a copy to Cloudflare R2 (safety-net backup).
  5. Upload the file to Telegram.
  6. Delete R2 object and local file once Telegram upload succeeds.
"""

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import mimetypes
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlparse, urlencode, urljoin, urlunparse

import aiohttp
import boto3
from botocore.config import Config as BotoConfig
from dotenv import load_dotenv
from pyrogram import Client, filters
from pyrogram.enums import ChatMemberStatus, ParseMode
from pyrogram.errors import FloodWait, UserNotParticipant
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# Secrets can come from either source, and no code branching is needed for
# that: a local ".env" file (loaded below, for local dev) and GitHub Actions
# repo secrets (https://docs.github.com/actions/security-guides/using-secrets-in-github-actions)
# both ultimately just set process environment variables, which os.getenv()
# reads uniformly. In a workflow, secrets get exposed to the job like:
#
#   env:
#     API_ID: ${{ secrets.API_ID }}
#     API_HASH: ${{ secrets.API_HASH }}
#     BOT_TOKEN: ${{ secrets.BOT_TOKEN }}
#     R2_ACCOUNT_ID: ${{ secrets.R2_ACCOUNT_ID }}
#     R2_ACCESS_KEY_ID: ${{ secrets.R2_ACCESS_KEY_ID }}
#     R2_SECRET_ACCESS_KEY: ${{ secrets.R2_SECRET_ACCESS_KEY }}
#     R2_BUCKET_NAME: ${{ secrets.R2_BUCKET_NAME }}
#
# load_dotenv() only fills in variables that aren't already set in the
# environment, and does nothing (no error) if no .env file is present, so
# it's safe to call unconditionally in both places.
load_dotenv()

REQUIRED_ENV_VARS = [
    "API_ID", "API_HASH", "BOT_TOKEN",
    "R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME",
]
_missing = [v for v in REQUIRED_ENV_VARS if not os.getenv(v)]
if _missing:
    raise SystemExit(
        "Missing required environment variables: "
        + ", ".join(_missing)
        + "\nSet these either in a local .env file (copy .env.example to .env "
        "and fill in the values) or, if running in GitHub Actions, as repo/"
        "environment secrets mapped into the job's `env:` block "
        "(Settings > Secrets and variables > Actions)."
    )

API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")
BOT_TOKEN = os.getenv("BOT_TOKEN")

R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME")

R2_ENDPOINT_URL = os.getenv("R2_ENDPOINT_URL") or f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

if not os.getenv("R2_ENDPOINT_URL") and not re.fullmatch(r"[0-9a-fA-F]{32}", R2_ACCOUNT_ID or ""):
    raise SystemExit(
        "R2_ACCOUNT_ID doesn't look like a Cloudflare account ID (should be a 32-character "
        "hex string). It's easy to accidentally paste an API token there instead — find the "
        "real account ID on the R2 Overview page in the Cloudflare dashboard, or in the URL "
        "https://dash.cloudflare.com/<account-id>/r2. Alternatively, set R2_ENDPOINT_URL "
        "directly (in your .env, or as an R2_ENDPOINT_URL repo secret) to skip this check."
    )

MAX_CONCURRENT_DOWNLOADS = int(os.getenv("MAX_CONCURRENT_DOWNLOADS", "2"))
MAX_CONCURRENT_UPLOADS = int(os.getenv("MAX_CONCURRENT_UPLOADS", "2"))
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "2000"))
DOWNLOAD_DIR = os.getenv("DOWNLOAD_DIR", "./downloads")
PRESIGNED_URL_EXPIRY = int(os.getenv("PRESIGNED_URL_EXPIRY_SECONDS", "3600"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
CHUNK_SIZE_BYTES = int(os.getenv("CHUNK_SIZE_MB", "50")) * 1024 * 1024
MAX_CHUNK_WORKERS = int(os.getenv("MAX_CHUNK_WORKERS", "4"))
FFMPEG_PATH = os.getenv("FFMPEG_PATH", "ffmpeg")

_allowed_raw = os.getenv("ALLOWED_USER_IDS", "").strip()
ALLOWED_USER_IDS = {int(x) for x in _allowed_raw.split(",") if x.strip()} if _allowed_raw else set()

_admin_raw = os.getenv("ADMIN_USER_IDS", "").strip()
ADMIN_USER_IDS = {int(x) for x in _admin_raw.split(",") if x.strip()} if _admin_raw else set()

COOLDOWN_MINUTES = int(os.getenv("COOLDOWN_MINUTES", "30"))
COOLDOWN_SECONDS = COOLDOWN_MINUTES * 60

VIDEO_EXTENSIONS = {".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".ts"}
HLS_EXTENSIONS = {".m3u8", ".m3u"}

# --------------------------------------------------------------------------
# Domain-specific headers & cookies
# --------------------------------------------------------------------------

DOMAIN_HEADERS = {
    "reelplexi.com": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://reelplexi.com/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "default": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Upgrade-Insecure-Requests": "1",
    }
}

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logging.getLogger("pyrogram").setLevel(logging.WARNING)
logger = logging.getLogger("downloader_bot")

# --------------------------------------------------------------------------
# Cloudflare R2 client
# --------------------------------------------------------------------------

s3_client = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT_URL,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name="auto",
    config=BotoConfig(signature_version="s3v4"),
)


async def upload_to_r2(local_path: str, key: str) -> None:
    await asyncio.to_thread(s3_client.upload_file, local_path, R2_BUCKET_NAME, key)


async def delete_from_r2(key: str) -> None:
    try:
        await asyncio.to_thread(s3_client.delete_object, Bucket=R2_BUCKET_NAME, Key=key)
    except Exception:
        logger.exception("Failed to delete R2 object %s", key)


def presigned_r2_url(key: str) -> str:
    return s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": R2_BUCKET_NAME, "Key": key},
        ExpiresIn=PRESIGNED_URL_EXPIRY,
    )

# --------------------------------------------------------------------------
# HTML Media Extractor
# --------------------------------------------------------------------------

class MediaExtractor:
    """Extract direct media URLs from HTML pages, JavaScript, and meta tags."""

    @staticmethod
    @staticmethod
    def extract_from_html(html: str, base_url: str) -> list[dict]:
        """Extract all candidate media URLs from HTML content."""
        candidates = []

        # 1. <video src="..."> or <video><source src="..."></video>
        video_src = re.findall("<video[^>]+src=[\'\"]([^\'\"]+)[\'\"]", html, re.IGNORECASE)
        for url in video_src:
            candidates.append({"url": urljoin(base_url, url), "source": "<video src>"})

        source_src = re.findall("<source[^>]+src=[\'\"]([^\'\"]+)[\'\"]", html, re.IGNORECASE)
        for url in source_src:
            candidates.append({"url": urljoin(base_url, url), "source": "<source src>"})

        # 2. <iframe src="..."> (embed players)
        iframe_src = re.findall("<iframe[^>]+src=[\'\"]([^\'\"]+)[\'\"]", html, re.IGNORECASE)
        for url in iframe_src:
            candidates.append({"url": urljoin(base_url, url), "source": "<iframe src>"})

        # 3. OpenGraph meta tags
        og_video = re.findall("<meta[^>]+property=[\'\"]og:video[\'\"][^>]+content=[\'\"]([^\'\"]+)[\'\"]", html, re.IGNORECASE)
        for url in og_video:
            candidates.append({"url": urljoin(base_url, url), "source": "og:video meta"})

        og_video_secure = re.findall("<meta[^>]+property=[\'\"]og:video:secure_url[\'\"][^>]+content=[\'\"]([^\'\"]+)[\'\"]", html, re.IGNORECASE)
        for url in og_video_secure:
            candidates.append({"url": urljoin(base_url, url), "source": "og:video:secure_url meta"})

        # 4. Twitter card meta
        twitter_video = re.findall("<meta[^>]+name=[\'\"]twitter:player:stream[\'\"][^>]+content=[\'\"]([^\'\"]+)[\'\"]", html, re.IGNORECASE)
        for url in twitter_video:
            candidates.append({"url": urljoin(base_url, url), "source": "twitter:player:stream meta"})

        # 5. JSON-LD structured data
        jsonld_blocks = re.findall("<script[^>]*type=[\'\"]application/ld\\+json[\'\"][^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
        for block in jsonld_blocks:
            try:
                data = json.loads(block.strip())
                if isinstance(data, dict):
                    for key in ["contentUrl", "embedUrl", "url", "thumbnailUrl"]:
                        if key in data and isinstance(data[key], str) and data[key].startswith(("http", "//")):
                            candidates.append({"url": urljoin(base_url, data[key]), "source": f"JSON-LD {key}"})
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            for key in ["contentUrl", "embedUrl", "url"]:
                                if key in item and isinstance(item[key], str) and item[key].startswith(("http", "//")):
                                    candidates.append({"url": urljoin(base_url, item[key]), "source": f"JSON-LD {key}"})
            except json.JSONDecodeError:
                pass

        # 6. JavaScript variables containing URLs (var videoUrl = "...")
        js_patterns = [
            "var\\s+\\w*[Vv]ideo\\w*\\s*=\\s*[\'\"]([^\'\"]+)[\'\"]",
            "var\\s+\\w*[Ss]tream\\w*\\s*=\\s*[\'\"]([^\'\"]+)[\'\"]",
            "var\\s+\\w*[Uu]rl\\w*\\s*=\\s*[\'\"]([^\'\"]+)[\'\"]",
            "[\'\"]?url[\'\"]?\\s*:\\s*[\'\"]([^\'\"]+\\.(?:mp4|m3u8|mkv|webm|ts|mov))[\'\"]",
            "[\'\"]?src[\'\"]?\\s*:\\s*[\'\"]([^\'\"]+\\.(?:mp4|m3u8|mkv|webm|ts|mov))[\'\"]",
            "[\'\"]?file[\'\"]?\\s*:\\s*[\'\"]([^\'\"]+\\.(?:mp4|m3u8|mkv|webm|ts|mov))[\'\"]",
            "[\'\"]?video_url[\'\"]?\\s*:\\s*[\'\"]([^\'\"]+)[\'\"]",
            "[\'\"]?stream_url[\'\"]?\\s*:\\s*[\'\"]([^\'\"]+)[\'\"]",
            "[\'\"]?playbackUrl[\'\"]?\\s*:\\s*[\'\"]([^\'\"]+)[\'\"]",
            "[\'\"]?contentUrl[\'\"]?\\s*:\\s*[\'\"]([^\'\"]+)[\'\"]",
        ]
        for pattern in js_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                url = match.strip().replace("\\/", "/")
                if url.startswith(("http", "//")):
                    candidates.append({"url": urljoin(base_url, url), "source": "JS variable"})

        # 7. Raw m3u8/mp4 links in the HTML
        raw_media = re.findall("[\'\"](https?://[^\'\"]+\\.(?:m3u8|mp4|mkv|webm|ts|mov))[\'\"]", html, re.IGNORECASE)
        for url in raw_media:
            candidates.append({"url": url, "source": "raw link in HTML"})

        # 8. <a href="..."> with video file extensions
        a_href = re.findall("<a[^>]+href=[\'\"]([^\'\"]+\\.(?:mp4|m3u8|mkv|webm|ts|mov))[\'\"]", html, re.IGNORECASE)
        for url in a_href:
            candidates.append({"url": urljoin(base_url, url), "source": "<a href>"})

        # 9. data-* attributes
        data_urls = re.findall("data-(?:url|src|video|stream)=[\'\"]([^\'\"]+)[\'\"]", html, re.IGNORECASE)
        for url in data_urls:
            if "." in url:
                candidates.append({"url": urljoin(base_url, url), "source": "data-* attribute"})

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for c in candidates:
            if c["url"] not in seen:
                seen.add(c["url"])
                unique.append(c)
        return unique


    @staticmethod
    def is_html_response(content_type: str | None, url: str) -> bool:
        """Check if response is HTML or looks like a webpage."""
        if content_type:
            ct = content_type.lower()
            if any(x in ct for x in ["text/html", "application/xhtml", "text/plain"]):
                return True
        # If URL has no file extension, it's likely a page
        path = urlparse(url).path
        if not path or "." not in os.path.basename(path):
            return True
        return False

# --------------------------------------------------------------------------
# Stream Auditor
# --------------------------------------------------------------------------

class StreamAuditor:
    # ------------------------------------------------------------------
    # Reelplexi / Labafilms API scraper
    # ------------------------------------------------------------------
    REELPLEXI_DOMAINS = {"reelplexi.com", "labafilms.online", "www.labafilms.online"}
    REELPLEXI_API_BASE = "https://api.reelplexi.com/v1"

    @staticmethod
    def is_reelplexi(url: str) -> bool:
        return urlparse(url).netloc.replace("www.", "") in StreamAuditor.REELPLEXI_DOMAINS

    @staticmethod
    def extract_movie_id(url: str) -> str | None:
        """Extract numeric movie ID from paths like /movies/4346 or /watch/4346."""
        patterns = [
            r"/movies/(\d+)",
            r"/watch/(\d+)",
            r"/film/(\d+)",
            r"/title/(\d+)",
            r"/movie/(\d+)",
            r"/(\d+)$",
        ]
        for pat in patterns:
            m = re.search(pat, url, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    @staticmethod
    async def scrape_reelplexi(session: aiohttp.ClientSession, movie_id: str, headers: dict, audit_log: list) -> str | None:
        """Try multiple API endpoints to get the stream URL for a reelplexi movie."""
        endpoints = [
            f"{StreamAuditor.REELPLEXI_API_BASE}/movies/{movie_id}/stream",
            f"{StreamAuditor.REELPLEXI_API_BASE}/stream/movie/{movie_id}",
            f"{StreamAuditor.REELPLEXI_API_BASE}/movies/{movie_id}",
            f"{StreamAuditor.REELPLEXI_API_BASE}/embed/movie/{movie_id}",
        ]
        for endpoint in endpoints:
            try:
                audit_log.append(f"[*] Trying reelplexi API: {endpoint}")
                async with session.get(endpoint, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status >= 400:
                        audit_log.append(f"[-] API returned {resp.status}")
                        continue
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct:
                        data = await resp.json()
                        audit_log.append(f"[+] API JSON response: {json.dumps(data, indent=2)[:600]}")
                        # Look for stream_url, video_url, url fields
                        for key in ["stream_url", "video_url", "url", "src", "playbackUrl", "playback_url"]:
                            if key in data and isinstance(data[key], str) and data[key].startswith("http"):
                                audit_log.append(f"[CRITICAL] Found {key} in API response: {data[key][:200]}")
                                return data[key]
                    else:
                        text = await resp.text()
                        # Sometimes the API returns HTML with the data embedded
                        media_links = MediaExtractor.extract_from_html(text, endpoint)
                        if media_links:
                            audit_log.append(f"[+] Found {len(media_links)} links in API HTML response")
                            return media_links[0]["url"]
            except Exception as e:
                audit_log.append(f"[-] API endpoint failed: {e}")
        return None

    @staticmethod
    def decode_jwt_payload(token: str) -> dict | None:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload_b64 = parts[1]
            padding_needed = (4 - len(payload_b64) % 4) % 4
            payload_b64 += "=" * padding_needed
            decoded_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(decoded_bytes)
        except Exception as e:
            logger.debug("JWT decode failed: %s", e)
            return None

    @staticmethod
    def extract_jwt_from_url(url: str) -> tuple[str | None, dict | None]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for key in ("token", "jwt", "auth", "sig", "signature"):
            if key in params:
                token = params[key][0]
                payload = StreamAuditor.decode_jwt_payload(token)
                return token, payload
        path_segments = parsed.path.split("/")
        for segment in path_segments:
            if re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", segment):
                payload = StreamAuditor.decode_jwt_payload(segment)
                if payload:
                    return segment, payload
        return None, None

    @staticmethod
    def extract_direct_url_from_payload(payload: dict) -> str | None:
        candidates = ["url", "cdn_url", "direct_url", "stream_url", "file_url", "src", "source", "playbackUrl"]
        for key in candidates:
            if key in payload and isinstance(payload[key], str):
                return payload[key]
        def deep_search(obj):
            if isinstance(obj, dict):
                for v in obj.values():
                    result = deep_search(v)
                    if result:
                        return result
            elif isinstance(obj, list):
                for item in obj:
                    result = deep_search(item)
                    if result:
                        return result
            elif isinstance(obj, str) and obj.startswith(("http://", "https://")):
                return obj
            return None
        return deep_search(payload)

    @staticmethod
    def score_media_url(url: str) -> int:
        """Score a candidate URL. Higher = more likely to be direct file."""
        score = 0
        url_lower = url.lower()
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()

        # Direct file indicators in path (strong signal)
        if any(kw in path for kw in ["/download", "/raw", "/direct", "/cdn", "/file", "/media", "/stream"]):
            score += 100

        # Player page indicators (negative signal)
        if any(kw in path for kw in ["/play", "/watch", "/embed", "/player", "/view"]):
            score -= 50

        # API endpoints (neutral, might need further extraction)
        if any(kw in path for kw in ["/api/", "/api?"]):
            score += 20

        # File extension in actual path (not query string)
        path_ext = os.path.splitext(path)[1].lower()
        if path_ext in [".mp4", ".m3u8", ".webm", ".mkv", ".ts", ".mov", ".avi"]:
            score += 80

        # File extension in query string (weaker signal, could be fake)
        query_ext_match = re.search(r"\.(mp4|m3u8|webm|mkv|ts|mov|avi)(?:[&]|$)", query)
        if query_ext_match:
            score += 30

        # Direct CDN domains
        if any(kw in parsed.netloc.lower() for kw in ["cdn", "static", "media", "file", "download", "raw", "direct"]):
            score += 40

        # Known streaming params
        if any(kw in query for kw in ["token=", "jwt=", "auth=", "sig=", "expiry="]):
            score += 25

        # HLS playlist
        if ".m3u8" in url_lower:
            score += 60

        return score

    @staticmethod
    async def verify_direct_url(session: aiohttp.ClientSession, url: str, headers: dict) -> tuple[bool, str | None, str]:
        """Verify a URL actually returns a media file, not HTML."""
        try:
            async with session.head(url, headers=headers, allow_redirects=True, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                ct = resp.headers.get("Content-Type", "").lower()
                if ct and any(x in ct for x in ["video/", "audio/", "application/vnd.apple.mpegurl", "application/x-mpegurl"]):
                    return True, ct, f"HEAD check passed ({ct})"
                if resp.status >= 400:
                    return False, ct, f"HEAD returned {resp.status}"
        except Exception:
            pass

        # Fallback to GET with range to avoid downloading full file
        try:
            range_headers = headers.copy()
            range_headers["Range"] = "bytes=0-1023"
            async with session.get(url, headers=range_headers, allow_redirects=True, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                ct = resp.headers.get("Content-Type", "").lower()
                if ct and any(x in ct for x in ["video/", "audio/", "application/vnd.apple.mpegurl", "application/x-mpegurl"]):
                    return True, ct, f"GET range check passed ({ct})"
                # Check first bytes for HLS signature
                first_bytes = await resp.content.read(32)
                if first_bytes.startswith(b"#EXTM3U"):
                    return True, "application/x-mpegurl", "HLS signature detected"
                if first_bytes.startswith(b"\x00\x00\x00") or first_bytes.startswith(b"ftyp") or first_bytes.startswith(b"\x1aE\xdf\xa3"):
                    return True, ct or "video/*", "Binary media signature detected"
                if MediaExtractor.is_html_response(ct, url):
                    return False, ct, f"Returns HTML ({ct})"
                return True, ct, f"Unknown content type but not HTML ({ct})"
        except Exception as e:
            return False, None, f"Verification failed: {e}"

    @staticmethod
    async def audit_stream_url(url: str) -> dict:
        audit_log = []
        final_url = url
        headers = DOMAIN_HEADERS.get("default").copy()
        cookie_jar = aiohttp.CookieJar()

        domain = urlparse(url).netloc.replace("www.", "")
        if domain in DOMAIN_HEADERS:
            headers = DOMAIN_HEADERS[domain].copy()
            audit_log.append(f"[*] Detected domain '{domain}', using custom headers")

        audit_log.append(f"[*] Auditing stream URL: {url}")

        # === Reelplexi / Labafilms special handling ===
        if StreamAuditor.is_reelplexi(url):
            movie_id = StreamAuditor.extract_movie_id(url)
            if movie_id:
                audit_log.append(f"[*] Detected reelplexi movie ID: {movie_id}")
                timeout = aiohttp.ClientTimeout(total=30, sock_connect=10, sock_read=15)
                async with aiohttp.ClientSession(timeout=timeout, headers=headers, cookie_jar=cookie_jar) as session:
                    stream_url = await StreamAuditor.scrape_reelplexi(session, movie_id, headers, audit_log)
                    if stream_url:
                        # Decode JWT from stream_url
                        token, payload = StreamAuditor.extract_jwt_from_url(stream_url)
                        if payload:
                            audit_log.append(f"[!] Decoded JWT from stream_url: {json.dumps(payload, indent=2)[:500]}")
                            direct = StreamAuditor.extract_direct_url_from_payload(payload)
                            if direct:
                                audit_log.append(f"[CRITICAL] Extracted direct CDN from JWT: {direct}")
                                return {"final_url": direct, "audit_log": audit_log, "method": "reelplexi_api_jwt", "cookie_jar": cookie_jar}
                        # If no JWT or no direct URL in payload, use the stream_url itself
                        audit_log.append(f"[+] Using stream proxy URL (no JWT direct link found): {stream_url}")
                        return {"final_url": stream_url, "audit_log": audit_log, "method": "reelplexi_api_stream", "cookie_jar": cookie_jar}
            else:
                audit_log.append("[-] Could not extract movie ID from reelplexi URL")

        # Step 1: JWT extraction
        token, payload = StreamAuditor.extract_jwt_from_url(url)
        if payload:
            audit_log.append(f"[+] Extracted JWT token from URL")
            audit_log.append(f"[!] Decoded JWT Payload: {json.dumps(payload, indent=2)[:500]}")
            direct_url = StreamAuditor.extract_direct_url_from_payload(payload)
            if direct_url:
                audit_log.append(f"[CRITICAL] Exposed Direct CDN Link: {direct_url}")
                final_url = direct_url
                return {"final_url": final_url, "audit_log": audit_log, "method": "jwt_extraction", "cookie_jar": cookie_jar}

        # Step 2: Follow redirects
        audit_log.append("[*] Resolving redirects...")
        try:
            timeout = aiohttp.ClientTimeout(total=30, sock_connect=10, sock_read=10)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.head(url, allow_redirects=True, ssl=False) as resp:
                    if resp.status < 400 and str(resp.url) != url:
                        final_url = str(resp.url)
                        audit_log.append(f"[+] Redirect resolved to: {final_url}")
                if final_url == url:
                    async with session.get(url, allow_redirects=True, ssl=False) as resp:
                        final_url = str(resp.url)
                        if final_url != url:
                            audit_log.append(f"[+] Redirect resolved to: {final_url}")
        except Exception as e:
            audit_log.append(f"[-] Redirect resolution failed: {e}")

        # Step 3: Check if it's an API endpoint
        if final_url.endswith((".json", "/api/stream", "/api/video", "/player")) or "api" in final_url:
            audit_log.append("[*] URL looks like an API endpoint, attempting extraction...")
            try:
                timeout = aiohttp.ClientTimeout(total=30, sock_connect=10, sock_read=10)
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                    async with session.get(final_url, ssl=False) as resp:
                        if resp.content_type and "json" in resp.content_type:
                            data = await resp.json()
                            audit_log.append(f"[+] API Response: {json.dumps(data, indent=2)[:500]}")
                            direct_url = StreamAuditor.extract_direct_url_from_payload(data)
                            if direct_url:
                                final_url = direct_url
                                audit_log.append(f"[CRITICAL] Extracted direct URL from API: {final_url}")
                                return {"final_url": final_url, "audit_log": audit_log, "method": "api_extraction", "cookie_jar": cookie_jar}
            except Exception as e:
                audit_log.append(f"[-] API extraction failed: {e}")

        # Step 4: Check if response is HTML and parse it
        audit_log.append("[*] Checking if response is HTML...")
        try:
            timeout = aiohttp.ClientTimeout(total=30, sock_connect=10, sock_read=15)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(final_url, ssl=False) as resp:
                    content_type = resp.headers.get("Content-Type", "")
                    if MediaExtractor.is_html_response(content_type, final_url):
                        audit_log.append(f"[!] Server returned HTML page (Content-Type: {content_type})")
                        html = await resp.text()
                        media_links = MediaExtractor.extract_from_html(html, final_url)
                        if media_links:
                            audit_log.append(f"[+] Found {len(media_links)} candidate media URLs in HTML:")
                            # Score and sort all candidates
                            scored = [(StreamAuditor.score_media_url(link["url"]), link) for link in media_links]
                            scored.sort(key=lambda x: x[0], reverse=True)
                            for i, (score, link) in enumerate(scored[:8], 1):
                                audit_log.append(f"    {i}. [score:{score}] [{link['source']}] {link['url'][:120]}")

                            # Try candidates in score order, verify each one
                            audit_log.append("[*] Verifying candidates (highest score first)...")
                            for score, link in scored:
                                candidate = link["url"]
                                is_direct, ct, reason = await StreamAuditor.verify_direct_url(session, candidate, headers)
                                audit_log.append(f"    -> {candidate[:80]}... [score:{score}] {reason}")
                                if is_direct:
                                    final_url = candidate
                                    audit_log.append(f"[CRITICAL] Verified direct media URL: {final_url}")
                                    if final_url.endswith(tuple(HLS_EXTENSIONS)) or (ct and "mpegurl" in ct):
                                        return {"final_url": final_url, "audit_log": audit_log, "method": "html_parsing_verified_hls", "is_hls": True}
                                    return {"final_url": final_url, "audit_log": audit_log, "method": "html_parsing_verified"}

                            # If none verified, fallback to highest score without verification
                            audit_log.append("[!] No candidate verified as direct file. Fallback to highest score.")
                            final_url = scored[0][1]["url"]
                            audit_log.append(f"[+] Selected (unverified): {final_url}")
                            if final_url.endswith(tuple(HLS_EXTENSIONS)):
                                return {"final_url": final_url, "audit_log": audit_log, "method": "html_parsing_fallback_hls", "is_hls": True, "cookie_jar": cookie_jar}
                            return {"final_url": final_url, "audit_log": audit_log, "method": "html_parsing_fallback", "cookie_jar": cookie_jar}
                        else:
                            audit_log.append("[-] No media URLs found in HTML page")
                    else:
                        audit_log.append(f"[+] Response is not HTML ({content_type}), treating as direct file")
        except Exception as e:
            audit_log.append(f"[-] HTML parsing failed: {e}")

        # Step 5: HLS detection
        if any(final_url.endswith(ext) for ext in HLS_EXTENSIONS) or "m3u8" in final_url:
            audit_log.append("[*] Detected HLS/M3U8 stream")
            return {"final_url": final_url, "audit_log": audit_log, "method": "hls_stream", "is_hls": True, "cookie_jar": cookie_jar}

        audit_log.append(f"[+] Final resolved URL: {final_url}")
        return {"final_url": final_url, "audit_log": audit_log, "method": "direct", "cookie_jar": cookie_jar}

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def format_size(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


def make_progress_bar(percentage: float, width: int = 10) -> str:
    filled = min(width, max(0, int(percentage / 100 * width)))
    return "█" * filled + "░" * (width - filled)


def sanitize_filename(name: str) -> str:
    name = os.path.basename(name)
    name = re.sub(r'[^\w.\-() ]', "_", name).strip()
    return name[:200] or f"file_{int(time.time())}"


def determine_filename(url: str, content_disposition: str | None, content_type: str | None) -> str:
    if content_disposition:
        match = re.search(r"filename\*?=(?:UTF-8\'\')?\"?([^\";]+)\"?", content_disposition)
        if match:
            return sanitize_filename(match.group(1))
    base = os.path.basename(urlparse(url).path)
    base = base.split("?")[0]
    if base and "." in base:
        return sanitize_filename(base)
    ext = mimetypes.guess_extension(content_type.split(";")[0].strip()) if content_type else None
    return f"file_{int(time.time())}{ext or '.bin'}"


async def is_url_safe(url: str) -> tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http:// and https:// links are supported."
    hostname = parsed.hostname
    if not hostname:
        return False, "Couldn't parse a hostname from that URL."
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, "Couldn't resolve that hostname."
    for info in infos:
        ip = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
            return False, "That URL resolves to a private/internal address, which isn't allowed."
    return True, ""


async def safe_edit(message, text: str) -> None:
    try:
        await message.edit_text(text, parse_mode=ParseMode.MARKDOWN)
    except FloodWait as e:
        await asyncio.sleep(e.value)
        try:
            await message.edit_text(text, parse_mode=ParseMode.MARKDOWN)
        except Exception:
            pass
    except Exception:
        pass


async def update_progress(status_message, label: str, current: int, total: int) -> None:
    if total > 0:
        pct = current / total * 100
        bar = make_progress_bar(pct)
        await safe_edit(
            status_message,
            f"{label}\n\n[{bar}] {pct:.1f}%\n{format_size(current)} / {format_size(total)}",
        )
    else:
        await safe_edit(status_message, f"{label}\n{format_size(current)} (size unknown)")


def user_label(user) -> str:
    handle = f"@{user.username}" if user.username else (user.first_name or "Unknown")
    return f"{handle} (`{user.id}`)"


async def notify_admins(client, text: str) -> None:
    for admin_id in ADMIN_USER_IDS:
        try:
            await client.send_message(admin_id, text, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
        except Exception:
            logger.exception("Failed to notify admin %s", admin_id)


async def get_unjoined_channels(client, user_id: int) -> list[dict]:
    unjoined = []
    for channel in FORCE_SUB_CHANNELS:
        try:
            member = await client.get_chat_member(channel["chat"], user_id)
            if member.status in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED):
                unjoined.append(channel)
        except UserNotParticipant:
            unjoined.append(channel)
        except Exception:
            logger.warning("Couldn't verify membership for %s", channel["chat"])
    return unjoined


async def send_force_sub_prompt(message, unjoined: list[dict]) -> None:
    buttons = [
        [InlineKeyboardButton(f"📢 Join {ch['chat']}", url=ch["link"])]
        for ch in unjoined if ch["link"]
    ]
    buttons.append([InlineKeyboardButton("✅ I've Joined", callback_data="check_sub")])
    await message.reply_text(
        "🔒 *Join our channel(s) to use this bot:*\n\n"
        "Tap each button below to join, then tap *I've Joined* and resend your link.",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup(buttons),
    )

# --------------------------------------------------------------------------
# Pools
# --------------------------------------------------------------------------

class LimitedPool:
    def __init__(self, limit: int):
        self.limit = limit
        self._sem = asyncio.Semaphore(limit)
        self._active = 0
        self._waiting = 0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            self._waiting += 1
        await self._sem.acquire()
        async with self._lock:
            self._waiting -= 1
            self._active += 1

    async def release(self):
        async with self._lock:
            self._active -= 1
        self._sem.release()

    async def snapshot(self) -> tuple[int, int]:
        async with self._lock:
            return self._active, self._waiting


download_pool = LimitedPool(MAX_CONCURRENT_DOWNLOADS)
upload_pool = LimitedPool(MAX_CONCURRENT_UPLOADS)
user_jobs: dict[int, asyncio.Task] = {}
active_job_info: dict[int, dict] = {}
last_request_time: dict[int, float] = {}

# --------------------------------------------------------------------------
# Download functions
# --------------------------------------------------------------------------

async def download_hls_stream(url: str, output_path: str, status_message, headers: dict) -> bool:
    try:
        cmd = [
            FFMPEG_PATH,
            "-headers", "\r\n".join(f"{k}: {v}" for k, v in headers.items()),
            "-i", url,
            "-c", "copy",
            "-bsf:a", "aac_adtstoasc",
            "-y",
            output_path
        ]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        last_size = 0
        while process.returncode is None:
            await asyncio.sleep(5)
            if os.path.exists(output_path):
                current_size = os.path.getsize(output_path)
                if current_size > last_size:
                    await safe_edit(status_message, f"📥 *Downloading HLS stream...*\n{format_size(current_size)} downloaded")
                    last_size = current_size
            try:
                process.returncode = process.returncode
            except:
                pass
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error("FFmpeg failed: %s", stderr.decode()[-500:])
            return False
        return True
    except Exception as e:
        logger.exception("HLS download failed: %s", e)
        return False


async def download_chunk(session: aiohttp.ClientSession, url: str, start: int, end: int, 
                         part_path: str, headers: dict) -> None:
    chunk_headers = headers.copy()
    chunk_headers["Range"] = f"bytes={start}-{end}"
    async with session.get(url, headers=chunk_headers, ssl=False) as resp:
        resp.raise_for_status()
        with open(part_path, "wb") as f:
            async for data in resp.content.iter_chunked(256 * 1024):
                f.write(data)


async def download_file_concurrent(url: str, local_path: str, status_message, 
                                   total_size: int, headers: dict, cookie_jar: aiohttp.CookieJar | None = None) -> None:
    if total_size <= 0 or CHUNK_SIZE_BYTES <= 0:
        raise ValueError("Cannot use concurrent download without known file size")
    num_chunks = (total_size + CHUNK_SIZE_BYTES - 1) // CHUNK_SIZE_BYTES
    num_workers = min(MAX_CHUNK_WORKERS, num_chunks)
    part_files = []
    tasks = []
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=120)
    session_kwargs = {"timeout": timeout, "headers": headers}
    if cookie_jar is not None:
        session_kwargs["cookie_jar"] = cookie_jar
    async with aiohttp.ClientSession(**session_kwargs) as session:
        for i in range(num_chunks):
            start = i * CHUNK_SIZE_BYTES
            end = min(start + CHUNK_SIZE_BYTES - 1, total_size - 1)
            part_path = f"{local_path}.part{i}"
            part_files.append(part_path)
            tasks.append(download_chunk(session, url, start, end, part_path, headers))
        completed = 0
        for task in asyncio.as_completed(tasks):
            await task
            completed += 1
            pct = (completed / len(tasks)) * 100
            bar = make_progress_bar(pct)
            await safe_edit(
                status_message,
                f"📥 *Downloading (chunked)...*\n\n[{bar}] {pct:.1f}%\n({completed}/{len(tasks)} chunks)"
            )
    with open(local_path, "wb") as outfile:
        for part_path in part_files:
            with open(part_path, "rb") as infile:
                shutil.copyfileobj(infile, outfile)
            os.remove(part_path)


async def download_file(url: str, status_message, user_id: int, headers: dict | None = None,
                         max_html_retries: int = 3, cookie_jar: aiohttp.CookieJar | None = None) -> tuple[str, str]:
    """Download file with HTML retry, chunked concurrent downloads, and cookie persistence."""
    if headers is None:
        headers = DOMAIN_HEADERS["default"].copy()

    current_url = url
    retry_count = 0

    while retry_count <= max_html_retries:
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=60)
        session_kwargs = {"timeout": timeout, "headers": headers}
        if cookie_jar is not None:
            session_kwargs["cookie_jar"] = cookie_jar
        async with aiohttp.ClientSession(**session_kwargs) as session:
            async with session.get(current_url, allow_redirects=True, ssl=False) as resp:
                resp.raise_for_status()

                content_type = resp.headers.get("Content-Type", "")

                # If we got HTML, try to extract a better URL from it
                if MediaExtractor.is_html_response(content_type, current_url):
                    html = await resp.text()
                    media_links = MediaExtractor.extract_from_html(html, current_url)

                    if media_links:
                        scored = [(StreamAuditor.score_media_url(link["url"]), link) for link in media_links]
                        scored.sort(key=lambda x: x[0], reverse=True)

                        # Try to verify candidates in order
                        found_direct = False
                        for score, link in scored:
                            candidate = link["url"]
                            is_direct, ct, reason = await StreamAuditor.verify_direct_url(session, candidate, headers)
                            if is_direct:
                                retry_count += 1
                                current_url = candidate
                                await safe_edit(
                                    status_message,
                                    f"📥 *Server returned HTML. Auto-following link {retry_count}/{max_html_retries}...*\n"
                                    f"Found: {candidate[:100]}..."
                                )
                                found_direct = True
                                break

                        if found_direct:
                            continue  # Retry loop with new URL

                        # No verified candidates, try highest score anyway as last resort
                        retry_count += 1
                        current_url = scored[0][1]["url"]
                        await safe_edit(
                            status_message,
                            f"📥 *Server returned HTML. Trying best candidate {retry_count}/{max_html_retries}...*\n"
                            f"{current_url[:100]}..."
                        )
                        continue
                    else:
                        raise RuntimeError(
                            f"Server returned an HTML page instead of a file. "
                            f"The bot couldn't find any video links in the page. "
                            f"You may need to send a direct link (right-click → Copy video address)."
                        )

                # We have a non-HTML response, proceed with download
                total_size = int(resp.headers.get("Content-Length", 0))
                if MAX_FILE_SIZE_MB and total_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                    raise ValueError(f"File is {format_size(total_size)}, which exceeds the {MAX_FILE_SIZE_MB} MB limit.")

                filename = determine_filename(current_url, resp.headers.get("Content-Disposition"), resp.headers.get("Content-Type"))
                local_path = os.path.join(DOWNLOAD_DIR, f"{user_id}_{int(time.time())}_{filename}")

                accept_ranges = resp.headers.get("Accept-Ranges", "").lower() == "bytes"
                if total_size > CHUNK_SIZE_BYTES and accept_ranges and CHUNK_SIZE_BYTES > 0:
                    await safe_edit(status_message, f"📥 *Starting chunked download...*\n{format_size(total_size)} total, {MAX_CHUNK_WORKERS} parallel connections")
                    await download_file_concurrent(current_url, local_path, status_message, total_size, headers, cookie_jar)
                    return local_path, filename

                # Standard streamed download
                downloaded = 0
                last_update = time.time()
                with open(local_path, "wb") as f:
                    async for chunk in resp.content.iter_chunked(1024 * 1024):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if MAX_FILE_SIZE_MB and downloaded > MAX_FILE_SIZE_MB * 1024 * 1024:
                            raise ValueError(f"File exceeded the {MAX_FILE_SIZE_MB} MB limit during download.")
                        now = time.time()
                        if now - last_update > 3:
                            await update_progress(status_message, "📥 *Downloading...*", downloaded, total_size)
                            last_update = now

                return local_path, filename

    raise RuntimeError(f"Exceeded maximum HTML retries ({max_html_retries}). Could not find a direct file link.")



# --------------------------------------------------------------------------
# Upload & Send
# --------------------------------------------------------------------------

async def upload_and_send(client, message, status_message, local_path: str, filename: str, 
                          audit_log: list[str] | None = None) -> bool:
    r2_key = f"{message.from_user.id}/{os.path.basename(local_path)}"
    uploaded_to_r2 = False
    link = None

    try:
        await safe_edit(status_message, "☁️ *Backing up to cloud storage...*")
        await upload_to_r2(local_path, r2_key)
        uploaded_to_r2 = True
        link = presigned_r2_url(r2_key)

        await safe_edit(status_message, "📤 *Uploading to Telegram...*")
        last_update = {"t": 0.0}

        async def progress(current, total):
            now = time.time()
            if now - last_update["t"] > 3 or current == total:
                await update_progress(status_message, "📤 *Uploading to Telegram...*", current, total)
                last_update["t"] = now

        ext = os.path.splitext(filename)[1].lower()
        if ext in VIDEO_EXTENSIONS or ext in HLS_EXTENSIONS:
            await client.send_video(
                chat_id=message.chat.id,
                video=local_path,
                caption=f"🎬 {filename}",
                supports_streaming=True,
                progress=progress,
            )
        else:
            await client.send_document(
                chat_id=message.chat.id,
                document=local_path,
                caption=f"📄 {filename}",
                progress=progress,
            )

        await delete_from_r2(r2_key)
        await status_message.delete()
        return True

    except asyncio.CancelledError:
        if uploaded_to_r2:
            await delete_from_r2(r2_key)
        raise
    except Exception as e:
        logger.exception("Upload/send failed for %s", filename)
        audit_text = ""
        if audit_log:
            audit_text = "\n\n*Audit Log:*\n`" + "\n".join(audit_log[-5:]) + "`"
        if uploaded_to_r2 and link:
            await safe_edit(
                status_message,
                "⚠️ *Telegram upload failed:* " + str(e) + "\n\n"
                "Your file is safely backed up though — here's a temporary link "
                f"(valid ~{PRESIGNED_URL_EXPIRY // 60} min):\n{link}" + audit_text,
            )
        else:
            await safe_edit(status_message, f"❌ Upload failed: {e}" + audit_text)
        return False
    finally:
        if os.path.exists(local_path):
            os.remove(local_path)

# --------------------------------------------------------------------------
# Pyrogram handlers
# --------------------------------------------------------------------------

app = Client("video_downloader_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN, sleep_threshold=15)

START_TEXT = (
    "👋 *Advanced Stream Downloader*\n\n"
    "Send me a link and I'll:\n"
    "1️⃣ *Audit* \n"
    "2️⃣ *Resolve* \n"
    "3️⃣ *Parse* \n"
    "4️⃣ *Download* \n"
    "5️⃣ *Upload* \n"
    + (f"• Max file size: {MAX_FILE_SIZE_MB} MB\n" if MAX_FILE_SIZE_MB else "• No file size limit\n")
    + f"• Up to {MAX_CONCURRENT_DOWNLOADS} downloads and {MAX_CONCURRENT_UPLOADS} uploads at once\n"
    + f"• Chunked downloads: {MAX_CHUNK_WORKERS}x parallel, {CHUNK_SIZE_BYTES // 1024 // 1024} MB chunks\n"
    + (f"• Cooldown: 1 download every {COOLDOWN_MINUTES} min\n" if COOLDOWN_SECONDS else "")
    + "\nCommands: /status /queue /cancel /help /audit"
)

HELP_TEXT = (
    "*How to use this bot*\n\n"
    "1. Send any HTTP/HTTPS link\n"
    "2. I'll automatically extract the real direct link\n"
    "3. Large files use chunked parallel downloading\n"
    "4. HLS/M3U8 streams are merged to MP4 via ffmpeg\n"
    "5. Everything is backed up\n\n"
    "*Commands*\n"
    "/status — see queue and your cooldown status\n"
    "/queue — active jobs (admins only)\n"
    "/cancel — cancel your job\n"
    "/audit <url> — show stream audit log without downloading\n"
    "/help — show this message\n\n"
    + (f"\n\n1 download every {COOLDOWN_MINUTES} minutes." if COOLDOWN_SECONDS else "")
)


@app.on_message(filters.command("start") & filters.private)
async def start_cmd(client, message):
    await message.reply_text(START_TEXT, parse_mode=ParseMode.MARKDOWN)


@app.on_message(filters.command("help") & filters.private)
async def help_cmd(client, message):
    await message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


@app.on_message(filters.command("status") & filters.private)
async def status_cmd(client, message):
    user_id = message.from_user.id
    d_active, d_waiting = await download_pool.snapshot()
    u_active, u_waiting = await upload_pool.snapshot()
    text = (
        "📊 *Bot status*\n\n"
        f"⬇️ Downloads: {d_active}/{download_pool.limit} active, {d_waiting} queued\n"
        f"⬆️ Uploads: {u_active}/{upload_pool.limit} active, {u_waiting} queued\n"
        f"👥 Jobs in progress: {len(user_jobs)}\n"
    )
    info = active_job_info.get(user_id)
    if info:
        text += f"\n🔹 Your job: *{info['stage']}* — {info['filename'] or info['url']}"
    elif user_id not in ADMIN_USER_IDS and COOLDOWN_SECONDS:
        last = last_request_time.get(user_id)
        remaining = COOLDOWN_SECONDS - (time.time() - last) if last else 0
        if remaining > 0:
            mins, secs = divmod(int(remaining), 60)
            text += f"\n⏳ You can start another download in {mins}m {secs}s."
        else:
            text += "\n✅ You're free to start a download."
    await message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


@app.on_message(filters.command("queue") & filters.private)
async def queue_cmd(client, message):
    if message.from_user.id not in ADMIN_USER_IDS:
        await message.reply_text("This command is for admins only. Use /status for general queue info.")
        return
    if not active_job_info:
        await message.reply_text("No active jobs right now.")
        return
    lines = ["📋 *Active jobs*\n"]
    for uid, info in active_job_info.items():
        elapsed = int(time.time() - info["started_at"])
        mins, secs = divmod(elapsed, 60)
        lines.append(
            f"• {info['label']} — *{info['stage']}* — {mins}m {secs}s\n  {info['filename'] or info['url']}"
        )
    await message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


@app.on_message(filters.command("cancel") & filters.private)
async def cancel_cmd(client, message):
    task = user_jobs.get(message.from_user.id)
    if task and not task.done():
        task.cancel()
        await message.reply_text("🛑 Cancelling your active job...")
    else:
        await message.reply_text("You don't have an active job to cancel.")


@app.on_message(filters.command("audit") & filters.private)
async def audit_cmd(client, message):
    if len(message.command) < 2:
        await message.reply_text("Usage: `/audit <url>`", parse_mode=ParseMode.MARKDOWN)
        return
    url = message.command[1].strip()
    safe, reason = await is_url_safe(url)
    if not safe:
        await message.reply_text(f"❌ {reason}")
        return
    status = await message.reply_text("🔎 *Auditing stream URL...*", parse_mode=ParseMode.MARKDOWN)
    try:
        result = await StreamAuditor.audit_stream_url(url)
        log_text = "\n".join(result["audit_log"])
        final = result["final_url"]
        method = result["method"]
        text = (
            f"🔍 *Stream Audit Result*\n\n"
            f"*Method:* `{method}`\n"
            f"*Final URL:* `{final[:400]}{'...' if len(final) > 400 else ''}`\n\n"
            f"*Audit Log:*\n`{log_text[:3500]}{'...' if len(log_text) > 3500 else ''}`"
        )
        await status.edit_text(text, parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await status.edit_text(f"❌ Audit failed: {e}", parse_mode=ParseMode.MARKDOWN)


@app.on_callback_query(filters.regex("^check_sub$"))
async def check_sub_callback(client, callback_query):
    user_id = callback_query.from_user.id
    unjoined = await get_unjoined_channels(client, user_id)
    if unjoined:
        await callback_query.answer("You still need to join all the channels first.", show_alert=True)
        return
    await callback_query.answer("✅ Thanks for joining! Send me your link to get started.", show_alert=True)
    try:
        await callback_query.message.delete()
    except Exception:
        pass


@app.on_message(filters.text & filters.private & ~filters.command(["start", "help", "status", "queue", "cancel", "audit"]))
async def handle_links(client, message):
    user_id = message.from_user.id
    is_admin = user_id in ADMIN_USER_IDS

    if ALLOWED_USER_IDS and user_id not in ALLOWED_USER_IDS and not is_admin:
        await message.reply_text("⛔ You're not authorized to use this bot.")
        return

    if FORCE_SUB_CHANNELS and not is_admin:
        unjoined = await get_unjoined_channels(client, user_id)
        if unjoined:
            await send_force_sub_prompt(message, unjoined)
            return

    url = message.text.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        await message.reply_text("Please send a valid HTTP/HTTPS download link.")
        return

    existing = user_jobs.get(user_id)
    if existing and not existing.done():
        await message.reply_text("⚠️ You already have a job running. Use /cancel to stop it, or /status to check the queue.")
        return

    if not is_admin and COOLDOWN_SECONDS:
        last = last_request_time.get(user_id)
        if last is not None:
            elapsed = time.time() - last
            if elapsed < COOLDOWN_SECONDS:
                mins, secs = divmod(int(COOLDOWN_SECONDS - elapsed), 60)
                await message.reply_text(
                    f"⏳ Please wait {mins}m {secs}s before starting another download "
                    f"(limit: 1 every {COOLDOWN_MINUTES} min)."
                )
                return

    last_request_time[user_id] = time.time()
    user_jobs[user_id] = asyncio.create_task(run_job(client, message, url))

# --------------------------------------------------------------------------
# Job pipeline
# --------------------------------------------------------------------------

async def run_job(client, message, url: str) -> None:
    user_id = message.from_user.id
    label = user_label(message.from_user)
    status = await message.reply_text("🔎 *Validating link...*", parse_mode=ParseMode.MARKDOWN)
    local_path = None
    filename = None
    file_size = 0
    success = False
    audit_log = []

    active_job_info[user_id] = {
        "label": label, "url": url, "filename": None, 
        "stage": "validating", "started_at": time.time(),
    }

    try:
        safe, reason = await is_url_safe(url)
        if not safe:
            await safe_edit(status, f"❌ {reason}")
            return

        await notify_admins(client, f"📥 *Download started*\nUser: {label}\nLink: {url}")

        # === STREAM AUDIT PHASE ===
        active_job_info[user_id]["stage"] = "auditing stream"
        await safe_edit(status, "🔍 *Auditing stream URL for direct links...*")

        audit_result = await StreamAuditor.audit_stream_url(url)
        audit_log = audit_result["audit_log"]
        final_url = audit_result["final_url"]
        is_hls = audit_result.get("is_hls", False)
        cookie_jar = audit_result.get("cookie_jar")  # Preserve cookies from audit phase

        if audit_result["method"] != "direct":
            await safe_edit(status, f"🔍 *Extracted direct URL via {audit_result['method']}*")
            logger.info("Stream audit for %s: %s", url, audit_result["method"])

        domain = urlparse(final_url).netloc.replace("www.", "")
        headers = DOMAIN_HEADERS.get(domain, DOMAIN_HEADERS["default"]).copy()

        # === DOWNLOAD PHASE ===
        d_active, d_waiting = await download_pool.snapshot()
        active_job_info[user_id]["stage"] = "queued (download)" if d_active >= download_pool.limit else "downloading"
        if d_active >= download_pool.limit:
            await safe_edit(status, f"⏳ *Queued for download...*\n{d_active}/{download_pool.limit} slots busy, {d_waiting} ahead of you.")

        await download_pool.acquire()
        active_job_info[user_id]["stage"] = "downloading"
        try:
            if is_hls:
                filename = f"stream_{int(time.time())}.mp4"
                local_path = os.path.join(DOWNLOAD_DIR, f"{user_id}_{int(time.time())}_{filename}")
                hls_success = await download_hls_stream(final_url, local_path, status, headers)
                if not hls_success:
                    raise RuntimeError("HLS download via ffmpeg failed")
            else:
                local_path, filename = await download_file(final_url, status, user_id, headers, cookie_jar=cookie_jar)

            active_job_info[user_id]["filename"] = filename
            file_size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        finally:
            await download_pool.release()

        # === UPLOAD PHASE ===
        u_active, u_waiting = await upload_pool.snapshot()
        active_job_info[user_id]["stage"] = "queued (upload)" if u_active >= upload_pool.limit else "uploading"
        if u_active >= upload_pool.limit:
            await safe_edit(status, f"⏳ *Queued for upload...*\n{u_active}/{upload_pool.limit} slots busy, {u_waiting} ahead of you.")

        await upload_pool.acquire()
        active_job_info[user_id]["stage"] = "uploading"
        try:
            success = await upload_and_send(client, message, status, local_path, filename, audit_log)
        finally:
            await upload_pool.release()

        icon = "✅" if success else "⚠️"
        outcome = "delivered to Telegram" if success else "backed up to R2 only (Telegram upload failed)"
        await notify_admins(
            client,
            f"{icon} *Download finished*\nUser: {label}\nFile: `{filename}`\n"
            f"Size: {format_size(file_size)}\nResult: {outcome}\nMethod: {audit_result['method']}",
        )

    except asyncio.CancelledError:
        await safe_edit(status, "🛑 Job cancelled.")
        await notify_admins(client, f"🛑 *Job cancelled*\nUser: {label}\nLink: {url}")
    except Exception as e:
        logger.exception("Job failed for user %s", user_id)
        audit_text = ""
        if audit_log:
            audit_text = "\n\n*Audit Log:*\n`" + "\n".join(audit_log[-5:]) + "`"
        await safe_edit(status, f"❌ An error occurred: {e}" + audit_text)
        await notify_admins(client, f"❌ *Job failed*\nUser: {label}\nLink: {url}\nError: {e}")
    finally:
        user_jobs.pop(user_id, None)
        active_job_info.pop(user_id, None)
        if local_path and os.path.exists(local_path):
            os.remove(local_path)


def cleanup_download_dir() -> None:
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    for name in os.listdir(DOWNLOAD_DIR):
        path = os.path.join(DOWNLOAD_DIR, name)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _parse_force_sub_channels(raw: str) -> list[dict]:
    channels = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "|" in entry:
            chat, link = (p.strip() for p in entry.split("|", 1))
        else:
            chat, link = entry, None
        if link is None and chat.startswith("@"):
            link = f"https://t.me/{chat[1:]}"
        channels.append({"chat": chat, "link": link})
    return channels


FORCE_SUB_CHANNELS = _parse_force_sub_channels(os.getenv("FORCE_SUB_CHANNELS", ""))

if __name__ == "__main__":
    cleanup_download_dir()
    logger.info("Advanced Stream Downloader Bot is running...")
    app.run()
