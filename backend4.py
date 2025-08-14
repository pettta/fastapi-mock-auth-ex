
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
import jwt 


with open("secrets2.json") as f:
    secret_data = json.load(f)

### Utils for Auth: Exceptions & Verifiers 
class UnauthorizedException(HTTPException):
    def __init__(self, detail: str, **kwargs):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

class UnauthenticatedException(HTTPException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail="requires authentication")

class TokenVerifier():
    def __init__(self):
        self.config = secret_data 
        self.jwk_client = jwt.PyJWKClient(f"https://{self.config['AUTH_DOMAIN']}/.well-known/jwks.json" )  # TODO IMPLEMENT THIS IN THE AUTH PROXY 

    async def verify(self, security_scopes: SecurityScopes, token: Optional[HTTPAuthorizationCredentials]=Depends(HTTPBearer())):
        if token is None:
            raise UnauthenticatedException

        # This gets the 'kid' from the passed token
        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token.credentials).key
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


### Routes 
tokenVerifier = TokenVerifier() 
app = FastAPI()

@app.get("/secure-data")
def secure_data(auth_result: str=Security(tokenVerifier.verify)):
    return {"message": "This is secure data"}