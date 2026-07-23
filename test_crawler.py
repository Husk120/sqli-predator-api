import asyncio
import sys
import time
sys.path.insert(0, '.')

# Test the crawler directly
import httpx
from lib.crawler import Crawler

async def test_crawler():
    print("Testing crawler on httpbin.org/get...")
    async with httpx.AsyncClient() as client:
        crawler = Crawler(client, max_depth=0)
        forms, params = await crawler.crawl("http://httpbin.org/get")
        print(f"Forms found: {len(forms)}")
        print(f"Params found: {len(params)}")

        if forms:
            for i, f in enumerate(forms):
                print(f"  Form {i}: action={f.get('action')}, method={f.get('method')}")
                for inp in f.get('inputs', []):
                    print(f"    Input: name={inp.get('name')}, type={inp.get('type')}")

        if params:
            for i, p in enumerate(params[:5]):  # Show first 5
                print(f"  Param {i}: {p.get('name')}={p.get('value')} (from {p.get('base_url')})")
            if len(params) > 5:
                print(f"    ... and {len(params)-5} more")

if __name__ == "__main__":
    asyncio.run(test_crawler())