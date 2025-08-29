from fastapi import FastAPI, Response
from pydantic import BaseModel
import random 

app = FastAPI()

@app.post('/login')
def login(response: Response):
    response.set_cookie(
        key="auth_token",
        value=f"test{random.randint(1000, 9999)}",
        httponly=True,
        secure=True,      # Set to True for HTTPS environments
        samesite="None"   # Use 'None' if frontend and backend are on different domains
    )
    return {"message": "Logged in"}

# To run:
# uvicorn cookie:app --reload --port 8000