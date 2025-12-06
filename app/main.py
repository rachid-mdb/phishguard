from fastapi import FastAPI

app = FastAPI(title="PhishGuard API")


@app.get("/")
def read_root():
    return {"message": "PhishGuard API is running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}