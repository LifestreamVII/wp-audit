"""
http_client.py — HTTP helper for wp_audit.
"""

from typing import Optional

import requests

from config import REQUEST_TIMEOUT, USER_AGENT, log


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

class HTTP:
    session: requests.Session

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def get(self, url: str, *, silent: bool = False, **kwargs) -> Optional[requests.Response]:
        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
            return resp
        except requests.exceptions.SSLError as e:
            if not silent:
                log.warning("SSL error for %s: %s", url, e)
        except requests.exceptions.ConnectionError as e:
            if not silent:
                log.warning("Connection error for %s: %s", url, e)
        except requests.exceptions.Timeout:
            if not silent:
                log.warning("Timeout for %s", url)
        except requests.exceptions.RequestException as e:
            if not silent:
                log.warning("Request error for %s: %s", url, e)
        return None


http = HTTP()
