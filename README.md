# SQLi-PREDATOR API

FastAPI backend for SQL injection vulnerability detection (authorized testing only).

## Run locally
pip install -r requirements.txt
uvicorn api.index:app --reload

## Deploy on Render
- Build Command: pip install -r requirements.txt
- Start Command: uvicorn api.index:app --host 0.0.0.0 --port $PORT