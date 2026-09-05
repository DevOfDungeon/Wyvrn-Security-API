from fastapi import FastAPI

from sentinel.middleware import SentinelMiddleware


app = FastAPI(title="Sentinel Security Gateway")

app.add_middleware(SentinelMiddleware)


@app.get("/")
def home():
    return {
        "name": "Sentinel",
        "status": "running"
    }