from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.scan import router as scan_router
from api.scan_status import router as scan_status_router
from api.scan_report import router as scan_report_router
from api.scan_stop import router as scan_stop_router

app = FastAPI(title="SQLi-PREDATOR API", version="5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(scan_status_router)
app.include_router(scan_report_router)
app.include_router(scan_stop_router)

@app.get("/")
async def root():
    from lib.payloads import ALL_PAYLOADS
    return {
        "service": "SQLi-PREDATOR v5.0",
        "status": "operational",
        "payloads_loaded": len(ALL_PAYLOADS),
        "docs": "/docs",
    }
