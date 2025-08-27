# Fundamental Requirements 
python >= 3.10 

# Different Authorization Flows 
##  Resource Owner Password Credentials Grant (Password Flow): 
Notes:
- uses dependency injection with password flow: coupling the auth and API into one place 
- uses HS256 = HMAC using SHA256 for signing our JWTs 

First open a new bash instance, then depending on if you want: 

(1) Extremely Basic backend
```
python local_setup.py -v backend
```
Open http://localhost:9000/docs
Click the "Authorize" button.
Use the credentials:

User: johndoe

Password: secret

Now use the operation GET with the path /users/me.


(2) Adding JWT Tokens 
```
python local_setup.py -v backend2
```

we created a file here called secrets.json, usually you would use env vars or a secret store for this info, NEVER ACTUALLY HAVING THE FILE COMMITTED TO A PUBLIC REPO
we generated that using the command: 
```
openssl rand -hex 32
```

(3) Adding Scopes for scoped permissions 
```
python local_setup.py -v backend3
```

## Implicit Auth (not doing because it is not legacy for not being secure)
## Auth/Code Flow with PKCE 
Notes:
- uses dependency injection with auth flow: decoupling the auth and API into two APIs, necessitating a bit more logic but is much more secure
- uses RS256 = RSA using SHA256 for signing our JWTs. Has a private and public key: more secure & more complex 
- We have a tokenVerifier in our backend for tokens from our proxy, and another one in the proxy to handle auth from external sources & normalizing to our std, see the structure below:
```
iss = issuer URL: str
sub = subject id: str
aud = audience URL: str
iat = issued_at epoch time: int
exp = expires_at epoch time: int 
azp = authorized party: str 
gty = grant type: str
```

Open a bash instance, then run: 
```
python local_setup.py -v oauth-proxy
```

Now Open another bash instance, then run: 
```
python local_setup.py -v backend4
```


Now open another bash instance, then run: 
```
python local_setup.py -v frontend
```
This will do the code challenge logic and act sort of like what our SPA does. 