import asyncio
import sys
sys.path.insert(0, '.')

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

async def test_crawler_detailed():
    url = "http://httpbin.org/get?test=value&foo=bar"
    print(f"Fetching URL: {url}")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=15)
            print(f"Status: {resp.status_code}")
            print(f"Content-Type: {resp.headers.get('content-type')}")
            print(f"Text length: {len(resp.text)}")
            print(f"First 200 chars: {repr(text[:200])}")

            # Parse with BeautifulSoup
            soup = BeautifulSoup(resp.text, "lxml")
            print(f"Soup parsed. Find all forms: {len(soup.find_all('form'))}")
            for form in soup.find_all('form'):
                print(f"  Form: {form}")

            # Check for query parameters in the URL
            parsed = urlparse(url)
            if parsed.query:
                print(f"Query string: {parsed.query}")
                params = parse_qs(parsed.query)
                print(f"Parsed query params: {params}")
                for key, values in params.items():
                    print(f"  {key} = {values}")
            else:
                print("No query string in URL")

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_crawler_detailed())