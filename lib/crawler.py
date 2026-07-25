import logging
from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("sqli-predator")


class Crawler:
    def __init__(self, client: httpx.AsyncClient, max_depth: int = 1):
        self.client = client
        self.max_depth = max_depth
        self.visited = set()
        self.forms = []
        self.params = []
    
    async def crawl(self, start_url: str):
        await self._crawl_page(start_url, 0)
        return self.forms, self.params
    
    async def _crawl_page(self, url: str, depth: int):
        if depth > self.max_depth or url in self.visited:
            return
        self.visited.add(url)
        
        try:
            resp = await self.client.get(url, timeout=15)
            logger.info(f"[CRAWLER] GET {url} -> Status: {resp.status_code} | Final URL: {resp.url} | Content-Length: {len(resp.text)}")
            if resp.status_code >= 400:
                logger.warning(f"[CRAWLER] Skipping {url} due to HTTP status {resp.status_code}")
                return
        except Exception as e:
            logger.error(f"[CRAWLER] Failed to fetch {url}: {e}")
            return
        
        soup = BeautifulSoup(resp.text, "lxml")
        forms_found = soup.find_all("form")
        logger.info(f"[CRAWLER] Parsed {len(forms_found)} <form> elements on {resp.url}")
        
        for form_tag in forms_found:
            action = form_tag.get("action", "")
            action = urljoin(url, action) if action and action != "#" else url
            method = form_tag.get("method", "GET").upper()
            
            inputs = []
            for inp in form_tag.find_all(["input", "textarea"]):
                name = inp.get("name", "")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
            
            if inputs and not any(f["action"] == action for f in self.forms):
                self.forms.append({"action": action, "method": method, "inputs": inputs})
        
        parsed = urlparse(url)
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if not any(p["base_url"] == base and p["name"] == key for p in self.params):
                    self.params.append({"base_url": base, "name": key, "value": values[0]})
        
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(("#", "javascript:", "mailto:")):
                continue
            abs_url = urljoin(url, href)
            if urlparse(url).netloc == urlparse(abs_url).netloc:
                await self._crawl_page(abs_url.split("?")[0], depth + 1)
