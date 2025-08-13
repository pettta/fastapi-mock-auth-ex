# Fundamental Requirements 
python >= 3.10 

# Different Authorization Flows 
##  Resource Owner Password Credentials Grant (Password Flow): With Dependency Injection
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

Open a basj instance, then run: 
```
python local_setup.py -v oauth
```


Now open another bash instance, then run: 
```
python local_setup.py -v frontend
```
This will do the code challenge logic and act sort of like what our SPA does. 