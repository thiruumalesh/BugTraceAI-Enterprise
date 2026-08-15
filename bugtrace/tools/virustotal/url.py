from urllib.parse import urlparse

from .client import VirusTotalClient


async def lookup_url_domain(url: str):
    """
    Enrich the domain associated with a URL.

    This performs a domain reputation lookup only.
    It does not submit/upload the URL to VirusTotal.
    """

    parsed = urlparse(url)

    if not parsed.hostname:
        return {
            "success": False,
            "error": "Unable to extract hostname from URL",
        }

    client = VirusTotalClient()

    return await client.get_domain(
        parsed.hostname
    )
