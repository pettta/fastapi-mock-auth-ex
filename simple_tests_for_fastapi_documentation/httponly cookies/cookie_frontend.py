# cookie_frontend.py
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import httpx 

app = FastAPI()

# inline “template”
PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>FastAPI Hash Demo</title>
</head>
<body>
    <h1>Hash Demo</h1>
    <form method="post" action="/">
        <input type="text" name="message" placeholder="Enter a message" required />
        <button type="submit">Get Hash</button>
    </form>

    <h2>Result</h2>
    <p>{message}</p>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # read cookie (if any)
    msg = request.cookies.get("message", "")
    return HTMLResponse(PAGE.format(message=msg))

@app.post("/", response_class=HTMLResponse)
async def fetch_hash(request: Request, message: str = Form(...)):
    with httpx.Client() as client:
        httpx_resp = client.post("http://localhost:8000/login")
        token = client.cookies.get("auth_token")
        msg = httpx_resp.json()
    response = HTMLResponse(PAGE.format(message=msg))
    if token:
        response.set_cookie(key="auth_token", value=token, httponly=True)
    return response

# To run:
# uvicorn cookie_frontend:app --reload --port <any number other than 8000> 