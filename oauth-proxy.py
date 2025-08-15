import json 
from typing import Optional 
from fastapi import (
 FastAPI, 
 Depends, 
 HTTPException, 
 status,
 Security    
) 
from fastapi.security import (
 HTTPBearer,
 HTTPAuthorizationCredentials,
 SecurityScopes    
)
from fastapi.responses import (
 RedirectResponse   
)
import jwt 
import secrets




###=== In a normal app, you'd probably refactor this to a utils file ===### 
with open("secrets_auth.json") as f:
    secret_data = json.load(f)

class UnauthorizedException(HTTPException):
    def __init__(self, detail: str, **kwargs):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

class UnauthenticatedException(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail="requires authentication")

class OAuth2TokenVerifier:
    def __init__(self, provider: str):
        self.config = secret_data
        self.google_jwk_client = jwt.PyJWKClient(f"https://www.googleapis.com/oauth2/v3/certs" )
        self.microsoft_jwk_client = jwt.PyJWKClient(f"https://login.microsoftonline.com/common/discovery/v2.0/keys")
    
    async def verify(self, security_scopes: SecurityScopes, token: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer()), provider: Optional[str] = None ):
      if token is None:
        raise UnauthenticatedException

      # Determine which JWK client to use
      provider = provider or self.config.get("default_provider", "google")
      if provider == "google":
        jwks_client = self.google_jwk_client
      elif provider == "microsoft":
        jwks_client = self.microsoft_jwk_client
      else:
        jwks_client = None 

      if not jwks_client: 
          raise UnauthorizedException(str(error)) # TODO IMPLEMENT NORMAL EMAIL VERIFICATION RATHER THAN JUST RAISING AN EXCEPTION HERE 

      try:
          signing_key = jwks_client.get_signing_key_from_jwt(token.credentials).key
      except jwt.exceptions.PyJWKClientError as error:
          raise UnauthorizedException(str(error))
      except jwt.exceptions.DecodeError as error:
          raise UnauthorizedException(str(error))

      try:
          payload = jwt.decode(
              token.credentials,
              signing_key,
              algorithms=self.config.auth0_algorithms,
              audience=self.config.auth0_api_audience,
              issuer=self.config.auth0_issuer,
          )
      except Exception as error:
          raise UnauthorizedException(str(error))
  
      return payload
###===               Utils End               ===### 


AUTHORIZATION_TABLE = {}
# GLOBAL TABLE THAT MAPS THE GENERATED AUTH CODE TO {code_challenge: str, code_challenge_method: str, used: bool }

USERS_MOCK_DB = {} 
# USER FIELDS: internal_id: UUID, internal_refresh_token: str, google_id: str, microsoft_id: str, last_login: datetime, disabled: bool



###=== In a normal app, you'd refactor this to a routers file ===###
app = FastAPI()

@app.get("/auth")
async def authorize(code_challenge: str, code_challenge_method: str, redirect_uri: str):
    # Generate a unique one-time code
    one_time_code = secrets.token_urlsafe(32)
    while one_time_code in AUTHORIZATION_TABLE:
      one_time_code = secrets.token_urlsafe(32)

    # Store the code_challenge, code_challenge_method, and used=False in the global table
    AUTHORIZATION_TABLE[one_time_code] = {
      "code_challenge": code_challenge,
      "code_challenge_method": code_challenge_method,
      "used": False
    }

    login_url = f"/login?one_time_code={one_time_code}&redirect_uri={redirect_uri}"
    return RedirectResponse(url=login_url)

@app.post("/login")
async def login(one_time_code: str, redirect_uri: str):
    # TODO (5) Actually do the logic for POST /login
    # 1a. Have a form with username, password 
    # 1b. Have a form with "sign in with Google"
    # 2. For the sign in with google logic basically use the look up table to see if it maps to any existing account in the table, and if not have them create a new account by routing them to /register with some prefilled in info
    # 3. For the username/password form, validate the credentials by
    #   3a: Verify the username is in the database
    #   3b: Hash the password and compare it to the stored hash
    #   3c: verify the disabled field is not true
    # 4. update the AUTH_REQUEST_TABLE[one_time_code] entry with the user's internal_id, set enabled=true, timeout=5m from now in epoch time
    # 5. Redirect the user to the redirect URI (which would be the SPA) with a query parameter of one_time_code=one_time_code 
    #   --> this is where you implement logic on frontend to do a POST to /token w/ verifier and one-time-code
    pass

@app.post("/token")
async def token(code_verifier: str):
    # TODO (6) Actually do the logic for POST /token
    # 1a. Check if we have a one time code in the request body
    # 2a. If we do, look up the AUTH_REQUEST_TABLE[one_time_code] entry, see if (a) it exists, (b) is enabled, and (c) is not expired (d) the hash of the code verifier = the code challenge
    # 3a. If all those passed, generate a new 7 day refresh token to this user's database table, have it generate a JWT, return those as http-only cookies in the response
    # 1b. Check if we have a JWT & Refresh token in the request body: 
    # 2b: JWT & refresh not expired = do nothing 
    # 3b: JWT expired = create new refresh token, then use that to create a new JWT (refresh token rotation)
    # 4b: Refresh token expired = Error out the user --> frontend will give error message that tells them to relog in 
    pass


@app.get("/.well-known/jwks.json")
async def get_jwks():
    # TODO (4)
    # IMPLEMENT A /.well-known/jwks.json ENDPOINT For public key info we need our backend to see from us
    # Here's what googles looks like at  https://www.googleapis.com/oauth2/v3/certs (which you should know from part 2)
    """
    n = base64(modulus of RSA public key)
    e = base64(exponent of RSA public key)
    kid = unique identifier for the key 
    alg = algorithm used 
    kty = key type 
    use=intended use of the public key = signature verification

    {
      "keys": [
        {
          "n": "vr_b3oVWMRwGQknVn8EVKmsnKgQlFN6h5aRkEkvVw4x50w-C9pMxK4D9yyxo1ijiBTQ4A2ePr-VpEr3n1Yj0Kvz5JqfpQPlLC1pSmw_cJp_gLRMjlhyGCFV4zWa3XXrfEcpJrgd-Iz5e-rKIMPq1F0t6Luq-yj9EZSDi09QBdsj8ZFc47HSDzVUotVPuzkDgJlPYODfnd_7dz9H8rTR8Lu-uv-RCU308UgAphNNPlSISjUIhKU9j-an9kAtmOpMElqF4ChWQXFhxhn8DFHnQ_NhP80ugK3BT1hnM5KwlqocG90B0CDbBDA2JcdXCRZ8o_EsRZP43_jA49tU6Xc_8Vw",
          "e": "AQAB",
          "kid": "ba63b436836a939b795b4122d3f4d0d225d1c700",
          "alg": "RS256",
          "kty": "RSA",
          "use": "sig"
        },
        {
          "kid": "98dc55c8b209363a2451774bce5c42718d13cb7d",
          "use": "sig",
          "kty": "RSA",
          "alg": "RS256",
          "e": "AQAB",
          "n": "q44fdZly8llGEwROShl8cdTz9UHX4q-rqYg4xtLgMeMw4vsIBd2OojPMBa49HVLqEdDbOuAT4wsfcYCESGBvkPsGpWIV9XrZYoKfNhh-NFxgFTqS-RafneYe5_613G6q3ZCOk3kMcpqxej7pJ29RywCB5afQPddnF8pZa9_Bg_5TCdcLG5y84nV0SLhXfZ0aAMMPVt405VJCVcilGwvPpddmHfq2m37Q4gBilodjXnafQ6iysCUdI9qTdT3eW4hziYUAyF6nKtBcmzwdAUEG_yGxJJUFHIftWT_cljV4pzAjszkOiMOaOUGuRDvgn_8qTRo2xkwuQ5yoK7HepYTzJQ"
        }
      ]
    }
    """






