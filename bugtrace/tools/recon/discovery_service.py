from concurrent.futures import ThreadPoolExecutor

from bugtrace.tools.recon.katana import scan as katana_scan
from bugtrace.tools.recon.subfinder import scan as subfinder_scan
from bugtrace.tools.recon.waybackurls import scan as wayback_scan
from bugtrace.tools.recon.httpx import fingerprint


class DiscoveryService:

    def run(self, target):

        print("STEP 1", flush=True)

        urls = set()

        # ---------------------------------------
        # Extract domain
        # ---------------------------------------

        domain = (
            target.replace("https://", "")
                  .replace("http://", "")
                  .split("/")[0]
        )

        print("STEP 2 - Running Katana", flush=True)

        try:
            urls.update(katana_scan(target))
            print(f"[+] Katana: {len(urls)} URLs", flush=True)
        except Exception as e:
            print(f"[!] Katana failed: {e}", flush=True)

        print("STEP 3 - Running Subfinder", flush=True)

        try:
            subs = subfinder_scan(domain)

            for s in subs:
                if s.startswith("http"):
                    urls.add(s)
                else:
                    urls.add("https://" + s)

            print(f"[+] Total after Subfinder: {len(urls)}", flush=True)

        except Exception as e:
            print(f"[!] Subfinder failed: {e}", flush=True)

        print("STEP 4 - Running Wayback", flush=True)

        try:
            urls.update(wayback_scan(domain))
            print(f"[+] Total after Wayback: {len(urls)}", flush=True)

        except Exception as e:
            print(f"[!] Wayback failed: {e}", flush=True)

        if not urls:
            urls.add(target)

        # ---------------------------------------
        # Clean URLs
        # ---------------------------------------

        clean_urls = []

        for u in sorted(urls):

            if not u.startswith(("http://", "https://")):
                continue

            if len(u) > 300:
                continue

            clean_urls.append(u)

        clean_urls = list(dict.fromkeys(clean_urls))

        # Limit for now
        MAX_URLS = 100
        clean_urls = clean_urls[:MAX_URLS]

        print(f"[+] Fingerprinting {len(clean_urls)} URLs", flush=True)

        # ---------------------------------------
        # Worker
        # ---------------------------------------

        def worker(url):

            print(f"[HTTPX] {url}", flush=True)

            try:
                fp = fingerprint(url)
            except Exception as e:
                print(f"[!] Fingerprint failed: {url} : {e}")
                fp = ""

            return {
                "url": url,
                "fingerprint": fp
            }

        # ---------------------------------------
        # Parallel fingerprinting
        # ---------------------------------------

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(worker, clean_urls))

        print("Discovery Finished.", flush=True)

        return results
