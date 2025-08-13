from fastapi import FastAPI, Depends 
from fastapi.security import HTTPBearer

token_auth_scheme = HTTPBearer()
app = FastAPI()


@app.get("/secure-data")
def secure_data(token: str = Depends(token_auth_scheme)):
    return {"message": "This is secure data", "token": token}