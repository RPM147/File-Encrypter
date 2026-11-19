"""Optional GitHub Releases update checker (off by default)."""

import itertools
import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


def check_for_update(current_version: str):
    """
    Check the GitHub Releases API to see if a newer version is available.
    Returns a dict with 'version', 'url', and 'changelog' if found, else None.
    """
    url = "https://api.github.com/repos/RPM147/File-Encrypter/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status != 200:
                return None

            data = json.loads(response.read().decode("utf-8"))
            tag_name = data.get("tag_name", "")
            latest_version = tag_name[1:] if tag_name.startswith("v") else tag_name

            if not latest_version:
                return None

            clean_current = current_version.split("-")[0].split("+")[0]
            clean_latest = latest_version.split("-")[0].split("+")[0]
            current_parts = [int(x) for x in clean_current.split(".") if x.isdigit()]
            latest_parts = [int(x) for x in clean_latest.split(".") if x.isdigit()]

            while len(current_parts) < 3:
                current_parts.append(0)
            while len(latest_parts) < 3:
                latest_parts.append(0)

            is_newer = False
            for c, l in itertools.zip_longest(current_parts, latest_parts, fillvalue=0):
                if l > c:
                    is_newer = True
                    break
                if l < c:
                    break

            if is_newer:
                return {
                    "version": latest_version,
                    "url": data.get(
                        "html_url",
                        "https://github.com/RPM147/File-Encrypter/releases/latest",
                    ),
                    "changelog": data.get("body", ""),
                }

    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        TimeoutError,
        ValueError,
    ) as exc:
        logger.debug("Update check skipped due to expected error: %s", exc)

    return None


if __name__ == "__main__":
    from rpm_encrypter.services.constants import APP_VERSION

    print(check_for_update(APP_VERSION))
