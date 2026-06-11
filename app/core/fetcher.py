#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: @spacemany2k38
# 2025-12-24

import json
import os
import ssl
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from ..utils.logger import get_logger
from ..utils.paths import get_cache_path, get_temp_cache_dir
from ..utils.platform import get_platform_string
from .config import GITHUB_API, GITHUB_RAW, PYNOSAUR_ORG

_CERT_PATHS = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/opt/homebrew/etc/openssl/cert.pem",
    "/usr/local/etc/openssl/cert.pem",
]


def _build_ssl_context(verify):
    """Build an SSL context that works across macOS/Linux Python installs."""
    if not verify:
        return ssl._create_unverified_context()

    ctx = ssl.create_default_context()
    try:
        urllib.request.urlopen(
            urllib.request.Request("https://api.github.com"),
            timeout=5,
            context=ctx,
        )
        return ctx
    except urllib.error.URLError:
        pass

    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
        return ctx
    except (ImportError, OSError):
        pass

    for path in _CERT_PATHS:
        if os.path.isfile(path):
            try:
                ctx = ssl.create_default_context(cafile=path)
                return ctx
            except OSError:
                continue

    return None


class GitHubFetcher:
    """Fetches packages from GitHub pynosaur organization."""

    def __init__(self, verify_ssl=True):
        self.logger = get_logger()
        self.org = PYNOSAUR_ORG
        self.api_base = GITHUB_API
        self.raw_base = GITHUB_RAW
        self.verify_ssl = verify_ssl

        if not verify_ssl:
            self.ssl_context = ssl._create_unverified_context()
            self.logger.warning(
                'SSL verification disabled - not recommended for security!',
            )
        else:
            self.ssl_context = _build_ssl_context(verify=True)
            if self.ssl_context is None:
                self.logger.warning(
                    "Could not find CA certificates; falling back to unverified SSL",
                )
                self.ssl_context = ssl._create_unverified_context()

    def fetch_json(self, url, timeout=30):
        """Fetch a URL and return parsed JSON (None on error/404)."""
        try:
            req = urllib.request.Request(url)
            req.add_header('Accept', 'application/vnd.github.v3+json')

            with urllib.request.urlopen(
                req, timeout=timeout, context=self.ssl_context,
            ) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
        except urllib.error.URLError as e:
            self.logger.error(f"Network error: {e.reason}")
            return None

    def url_exists(self, url, timeout=5):
        """Check if a URL is reachable without downloading the body."""
        try:
            req = urllib.request.Request(url, method='HEAD')
            urllib.request.urlopen(
                req, timeout=timeout, context=self.ssl_context,
            )
            return True
        except (urllib.error.HTTPError, urllib.error.URLError):
            return False

    def _api_request(self, url):
        """Make API request to GitHub."""
        return self.fetch_json(url)

    def _download_file(self, url, dest_path):
        """Download file from URL."""
        self.logger.debug(f"Downloading from {url}")

        try:
            with urllib.request.urlopen(
                url, timeout=60, context=self.ssl_context,
            ) as response:
                total_size = response.getheader('Content-Length')
                if total_size:
                    total_size = int(total_size)
                    size_mb = total_size / (1024 * 1024)
                    self.logger.info(f"Downloading {dest_path.name} ({size_mb:.1f} MB)")

                content = response.read()

                dest_path.parent.mkdir(parents=True, exist_ok=True)
                with dest_path.open('wb') as f:
                    f.write(content)

                self.logger.info(f"Downloaded {dest_path.name}")
                return dest_path
        except urllib.error.URLError as e:
            self.logger.error(f"Download failed: {e.reason}")
            return None

    def _safe_extractall(self, tar, extract_root):
        """Manual member validation for Pythons without extraction
        filters: skip members that would land outside extract_root."""
        root = Path(extract_root).resolve()
        safe_members = []
        for member in tar.getmembers():
            target = (root / member.name).resolve()
            if root != target and root not in target.parents:
                self.logger.warning(
                    f"Skipping unsafe archive member: {member.name}",
                )
                continue
            safe_members.append(member)
        tar.extractall(path=extract_root, members=safe_members)

    def get_repo_info(self, app_name):
        """Get repository information."""
        url = f"{self.api_base}/repos/{self.org}/{app_name}"
        self.logger.debug(f"Fetching repo info: {url}")
        return self._api_request(url)

    def get_latest_release(self, app_name):
        """Get latest release information."""
        url = f"{self.api_base}/repos/{self.org}/{app_name}/releases/latest"
        self.logger.debug(f"Fetching latest release: {url}")
        return self._api_request(url)

    def get_release_by_tag(self, app_name, tag):
        """Get specific release by tag.

        Args:
            app_name: Name of the app
            tag: Tag name (e.g., "v0.1.0" or "0.1.0")

        Returns:
            Release info dict or None if not found
        """
        # Ensure tag has 'v' prefix
        if not tag.startswith('v'):
            tag = f"v{tag}"

        url = f"{self.api_base}/repos/{self.org}/{app_name}/releases/tags/{tag}"
        self.logger.debug(f"Fetching release {tag}: {url}")
        return self._api_request(url)

    def _download_release_asset(self, app_name, release, asset_name):
        """Download a named asset from a GitHub release."""
        assets = release.get("assets", []) if release else []
        match = next((a for a in assets if a.get("name") == asset_name), None)
        if not match:
            self.logger.warning(f"Release missing required asset: {asset_name}")
            return None

        download_url = match.get("browser_download_url")
        if not download_url:
            self.logger.error(f"Asset {asset_name} missing download URL")
            return None

        cache_path = get_cache_path(app_name, asset_name)
        result = self._download_file(download_url, cache_path)
        return result

    def download_binary(self, app_name, platform=None, version=None):
        """Download compiled binary for platform.

        Args:
            app_name: Name of the app
            platform: Platform string (default: auto-detect)
            version: Specific version to download (e.g., "0.1.0"), or None for latest

        Returns:
            Tuple of (binary_path, version) or (None, None) if not found
        """
        if platform is None:
            platform = get_platform_string()

        # Get specific or latest release
        if version:
            release = self.get_release_by_tag(app_name, version)
            if not release:
                self.logger.error(f"Release v{version} not found for {app_name}")
                return None, None
        else:
            release = self.get_latest_release(app_name)
            if not release:
                self.logger.debug("No releases found")
                return None, None

        version_tag = release.get("tag_name", "unknown")
        version_clean = str(version_tag).lstrip('v')
        self.logger.progress(
            f"Looking for binary: {app_name}-{version_clean}-{platform} "
            f"(or legacy {app_name}-{platform})",
        )
        # Versioned asset first, then legacy name-platform only
        candidates = [
            f"{app_name}-{version_clean}-{platform}",
            f"{app_name}-{platform}",
        ]
        cache_path = None
        for binary_name in candidates:
            cache_path = self._download_release_asset(
                app_name, release, binary_name,
            )
            if cache_path:
                break
        if not cache_path:
            self.logger.debug(f"No binary found for {platform}")
            return None, version_tag

        return cache_path, version_tag

    def download_source(self, app_name, ref="main", edge=False, version=None):
        """Download source code archive.

        Args:
            app_name: Name of the app
            ref: Git ref to download (default: main)
            edge: If True, always use main branch; if False, prefer latest release
            version: Specific version to download (e.g., "0.1.0"), overrides edge mode
        """
        self.logger.progress(f"Downloading source for {app_name}")

        # Use specific version if provided
        if version:
            tag = f"v{version}" if not version.startswith('v') else version
            url = f"{self.api_base}/repos/{self.org}/{app_name}/tarball/{tag}"
            cache_path = get_cache_path(app_name, f"{app_name}-{tag}.tar.gz")
            result = self._download_file(url, cache_path)
            if result:
                return result, tag
            self.logger.error(f"Failed to download source for version {version}")
            return None, None

        # Use latest release tag if not in edge mode
        if not edge:
            release = self.get_latest_release(app_name)
            if release:
                tag = release.get("tag_name", ref)
                url = f"{self.api_base}/repos/{self.org}/{app_name}/tarball/{tag}"
                cache_path = get_cache_path(app_name, f"{app_name}-{tag}.tar.gz")
                result = self._download_file(url, cache_path)
                if result:
                    return result, tag

        # Fallback to main branch (or always use main in edge mode)
        url = f"{self.api_base}/repos/{self.org}/{app_name}/tarball/{ref}"
        cache_path = get_cache_path(app_name, f"{app_name}-{ref}.tar.gz")

        result = self._download_file(url, cache_path)
        if result:
            return result, ref

        return None, None

    def download_app_directory(self, app_name, ref="main", edge=False, version=None):
        """Download full source tarball and extract.

        Args:
            app_name: Name of the app
            ref: Git ref to download (default: main)
            edge: If True, use main branch; if False, prefer latest release
            version: Specific version to download (e.g., "0.1.0")
        """
        (tar_path, version_tag) = self.download_source(
            app_name,
            ref,
            edge=edge,
            version=version,
        )
        if not tar_path:
            return None

        extract_root = get_temp_cache_dir(app_name) / "src"
        extract_root.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"Extracting source code...")
        try:
            with tarfile.open(tar_path, "r:gz") as tar:
                try:
                    # Reject absolute paths, traversal, and links that
                    # escape the extraction root (tar path traversal).
                    tar.extractall(path=extract_root, filter="data")
                except TypeError:
                    # Python builds without the filter parameter
                    self._safe_extractall(tar, extract_root)
            self.logger.info("Extraction complete")
        except tarfile.TarError as e:
            self.logger.error(f"Failed to extract source: {e}")
            return None

        # GitHub tarball creates top-level dir like pynosaur-yday-<hash>
        # Pick first directory
        children = [p for p in extract_root.iterdir() if p.is_dir()]
        if not children:
            self.logger.error("Extracted archive is empty")
            return None

        return children[0], version_tag

    def _download_directory(self, api_url, dest_dir):
        """Recursively download directory contents."""
        contents = self._api_request(api_url)
        if not contents:
            return

        dest_dir.mkdir(parents=True, exist_ok=True)

        for item in contents:
            if item["type"] == "file":
                file_url = item["download_url"]
                file_path = dest_dir / item["name"]
                self._download_file(file_url, file_path)
            elif item["type"] == "dir":
                self._download_directory(item["url"], dest_dir / item["name"])

