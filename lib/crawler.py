"""Async web crawler for form and parameter discovery."""

from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup


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
            if resp.status_code >= 400:
                return
        except:
            return
        
        soup = BeautifulSoup(resp.text, "lxml")
        
        for form_tag in soup.find_all("form"):
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
