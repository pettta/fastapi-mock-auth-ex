from fastapi import FastAPI

app = FastAPI()

@app.get("/oauth/health")
async def health():
	return {"status": "ok"}

# Placeholder oauth endpoints would go here.
