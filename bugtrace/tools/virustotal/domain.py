from .client import VirusTotalClient


async def lookup_domain(domain: str):
    """
    Perform VirusTotal domain reputation enrichment.
    """
    client = VirusTotalClient()
    return await client.get_domain(domain)
