import asyncio
import sys
import time
sys.path.insert(0, '.')

# Test the crawler on a page with parameters
import httpx
from lib.crawler import Crawler

async def test_crawler():
    # Test with a URL that has query parameters
    print("Testing crawler on http://httpbin.org/get?test=value&foo=bar...")
    async with httpx.AsyncClient() as client:
        crawler = Crawler(client, max_depth=0)
        forms, params = await crawler.crawl("http://httpbin.org/get?test=value&foo=bar")
        print(f"Forms found: {len(forms)}")
        print(f"Params found: {len(params)}")

        if forms:
            for i, f in enumerate(forms):
                print(f"  Form {i}: action={f.get('action')}, method={f.get('method')}")
                for inp in f.get('inputs', []):
                    print(f"    Input: name={inp.get('name')}, type={inp.get('type')}")

        if params:
            for i, p in enumerate(params):
                print(f"  Param {i}: {p.get('name')}={p.get('value')} (from {p.get('base_url')})")

if __name__ == "__main__":
    asyncio.run(test_crawler())