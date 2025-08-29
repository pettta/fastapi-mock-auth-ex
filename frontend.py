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

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, one_time_code: Optional[str] = Query(None), session_id: Optional[str] = Query(None)):
    # PKCE session setup: generate or retrieve code_verifier and code_challenge
    if not session_id:
        print("🆕 New session - generating fresh PKCE challenge")
        code_verifier = secrets.token_urlsafe(64)[:128]
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).rstrip(b'=').decode('utf-8')
        session_id = secrets.token_urlsafe(16)
        CODE_VERIFIERS[session_id] = code_verifier
        print(f"🔑 Stored code verifier for session: {session_id}")
    else:
        print(f"🔄 Returning session detected: {session_id}")
        code_verifier = CODE_VERIFIERS.get(session_id)
        if code_verifier:
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('utf-8')).digest()
            ).rstrip(b'=').decode('utf-8')
            print(f"✅ Found existing code verifier for session: {session_id}")
        else:
            print(f"❌ No code verifier found for session: {session_id}")
            # regenerate session
            code_verifier = secrets.token_urlsafe(64)[:128]
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode('utf-8')).digest()
            ).rstrip(b'=').decode('utf-8')
            session_id = secrets.token_urlsafe(16)
            CODE_VERIFIERS[session_id] = code_verifier
            print(f"🔑 Regenerated code verifier for new session: {session_id}")

    # Attempt refresh flow using existing cookies if no PKCE exchange
    tokens = None
    if not one_time_code:
        refresh_token = request.cookies.get('refresh_token')
        access_token = request.cookies.get('access_token')
        if refresh_token or access_token:
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
    # PKCE authorization code exchange
    if one_time_code and session_id:
        print(f"🎫 Processing authorization code: {one_time_code} for session: {session_id}")
        tokens = await exchange_code_for_tokens(one_time_code, session_id)
    response =  templates.TemplateResponse(
        "frontend.html",
        {
            "request": request,
            "code_challenge": code_challenge,
            "session_id": session_id,
            "tokens": tokens.get('msg'),
            "one_time_code": one_time_code,
            "code_verifier": code_verifier
        }
    ) 
    cookies_dict = {key: value for key, value in tokens.get('cookies', {}).items()}
    response.set_cookie(key="access_token", value=cookies_dict.get('access_token'), httponly=True, samesite='lax', domain='localhost', path='/')
    response.set_cookie(key="refresh_token", value=cookies_dict.get('refresh_token'), httponly=True, samesite='lax', domain='localhost', path='/')
    return response


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