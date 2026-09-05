from fastapi import FastAPI

app = FastAPI(title="Sentinel Security Gateway")


@app.get("/")
def home():
    return {
        "name": "Sentinel",
        "status": "running"
    }