from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.init_db import init_db
from app.api import test_config
from app.api import analyze
from app.api import dashboard
from app.ml.model_loader import load_model
app = FastAPI(
    title="ShieldX Threat Detection API",
    description="Agentic AI Phishing Detection Platform",
    version="1.0"
)

origins = [
    "http://localhost",
    "http://127.0.0.1",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
init_db()
load_model()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(test_config.router)
app.include_router(analyze.router)
app.include_router(dashboard.router)


@app.get("/")
def health_check():
    return {"status": "running", "service": "ShieldX"}
