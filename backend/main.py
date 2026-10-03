from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from scanner import scan

app = FastAPI(
    title="SecureScan",
    description="Passive web security assessment tool",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://securescan-i029.onrender.com",
],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def root():
    return {"name": "SecureScan", "status": "running", "mode": "passive"}


@app.post("/scan")
def start_scan(request: ScanRequest):
    try:
        return scan(str(request.url))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}")
