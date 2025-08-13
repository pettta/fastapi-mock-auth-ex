import secrets
import hashlib
import base64
import requests 

print("Frontend placeholder running. Add your frontend logic here.")


# Make sure that this isnt visible to user, but doesnt matter if user decompiles the program to get it since its random 
code_verifier = secrets.token_urlsafe(64)[:128]
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode('utf-8')).digest()
).rstrip(b'=').decode('utf-8')


# Send Code Challenge to the auth server
response = requests.post(
    "http://localhost:9001/auth",
    json={
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
)
print(f"Auth server response: {response.text}")


print(f"Code Verifier: {code_verifier}")
print(f"Code Challenge: {code_challenge}")