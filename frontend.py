import secrets
import hashlib
import base64
import webbrowser
from fastapi import FastAPI, Request, Response, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import httpx
from typing import Optional

app = FastAPI(title="Frontend App")
templates = Jinja2Templates(directory="templates")

# Store code verifiers temporarily (in production, use secure session storage)
CODE_VERIFIERS = {}

@app.get("/splash")
async def splash(
    request: Request,
    one_time_code: Optional[str] = Query(None),
    session_id:  Optional[str] = Query(None)
):
    # 1) generate / lookup PKCE: generate / retrieve code verifier/challenge 
    if not session_id:
        code_verifier = secrets.token_urlsafe(64)[:128]
        code_challenge = base64.urlsafe_b64encode(
          hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        session_id = secrets.token_urlsafe(16)
        CODE_VERIFIERS[session_id] = code_verifier
    else:
        code_verifier = CODE_VERIFIERS.get(session_id)
        code_challenge = base64.urlsafe_b64encode(
          hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

    # 2) if we dont have a one time code at this point, try to refresh tokens with cookies 
    tokens = None
    refresh_token = request.cookies.get('refresh_token')
    access_token = request.cookies.get('access_token')
    if (not one_time_code) and (refresh_token or access_token):
        tokens = await exchange_cookies_for_tokens(access_token, refresh_token)
        
    # 3) if we do have a one time code and a session id at this point,
    if one_time_code and session_id:
        print(f"🎫 Processing authorization code: {one_time_code} for session: {session_id}")
        tokens = await exchange_code_for_tokens(one_time_code, session_id)

    # 3) build a redirect back to “/” (no params)
    resp = RedirectResponse("/", status_code=302)

    # 4) persist PKCE state in cookies so "/" can read it
    resp.set_cookie("session_id",  session_id,  path="/")

    # 5) Copy Cookies from tokens endpoint to browser 
    token_cookies = tokens.get('cookies', {}) 
    if token_cookies:
        for ck in token_cookies.jar:
            resp.set_cookie(
              ck.name, ck.value,
              httponly=True,
              secure=False,    # True in prod
              samesite="lax",
              path="/",
              expires=ck.expires
            )
    return resp


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # Generate PKCE state for new sessions
    code_verifier = secrets.token_urlsafe(64)[:128]
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()
    session_id = secrets.token_urlsafe(16)
    CODE_VERIFIERS[session_id] = code_verifier
    
    # Check if user is already logged in
    access = request.cookies.get("access_token")
    refresh = request.cookies.get("refresh_token")
    
    return templates.TemplateResponse(
        "frontend.html",
        {
            "request": request,
            "tokens": {"access_token": access, "refresh_token": refresh, 
                       "msg": "You should not be accessing these in the code usually like I am here. its here for learning this process"},
            "session_id": session_id,
            "code_challenge": code_challenge,
            "code_verifier": code_verifier,  # For demo purposes only
        },
    )


@app.get("/logout")
async def logout(request: Request):
    """Logout endpoint that clears cookies and redirects to home"""
    print("🚪 User logging out - clearing cookies")
    resp = RedirectResponse("/", status_code=302)
    
    # Clear all authentication cookies
    resp.delete_cookie("access_token", path="/")
    resp.delete_cookie("refresh_token", path="/")
    resp.delete_cookie("session_id", path="/")
    
    return resp


# Exchange cookies for tokens 
async def exchange_cookies_for_tokens(access_token: Optional[str], refresh_token: Optional[str]):
    print("🔄 Attempting token refresh using cookies")
    async with httpx.AsyncClient() as client:
        httpx_response = await client.post(
            "http://localhost:9001/token",
            cookies={"access_token": access_token, "refresh_token": refresh_token}
        )
        if httpx_response.status_code == 200:
            tokens = httpx_response.json()
        else:
            print(f"❌ Refresh flow failed: {httpx_response.status_code} {httpx_response.text}")

# Exchange PKCE code for tokens
async def exchange_code_for_tokens(one_time_code: str, session_id: str):
    """Exchange one-time code for JWT tokens using session-specific code verifier"""
    print(f"🔍 Looking up code verifier for session: {session_id}")
    code_verifier = CODE_VERIFIERS.get(session_id)
    if not code_verifier:
        print(f"❌ No code verifier found for session: {session_id}")
        return {"error": f"Code verifier not found for session {session_id}"}
    print(f"✅ Found code verifier for session: {session_id}")
    print(f"🔄 Exchanging authorization code for tokens...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:9001/token",
                data={"one_time_code": one_time_code, "code_verifier": code_verifier}
            )
            if response.status_code == 200:
                print(f"🎉 Token exchange successful for session: {session_id}")
                CODE_VERIFIERS.pop(session_id, None)
                print(f"🧹 Cleaned up code verifier for session: {session_id}")
                print(f"We got cookies: {client.cookies}")
                return {"msg": response.json(), "cookies": client.cookies}
            else:
                print(f"❌ Token exchange failed: {response.status_code} - {response.text}")
                return {"error": f"Token exchange failed: {response.text}"}
    except Exception as e:
        print(f"💥 Token exchange error: {str(e)}")
        return {"error": f"Token exchange error: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)