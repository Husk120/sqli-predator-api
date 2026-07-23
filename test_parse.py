import asyncio
import sys
sys.path.insert(0, '.')

from urllib.parse import urlparse, parse_qs
import httpx

async def test_parse():
    url = "http://httpbin.org/get?test=value&foo=bar"
    print(f"URL: {url}")
    parsed = urlparse(url)
    print(f"Parsed: scheme={parsed.scheme}, netloc={parsed.netloc}, path={parsed.path}, query={parsed.query}")
    if parsed.query:
        params = parse_qs(parsed.query)
        print(f"Parsed query params: {params}")
        for key, values in params.items():
            print(f"  {key} = {values}")
    else:
        print("No query string")

if __name__ == "__main__":
    asyncio.run(test_parse())