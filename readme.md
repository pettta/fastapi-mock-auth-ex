# Fundamental Requirements 
python >= 3.10 

# Process to Run
## Simplest Verison
First open a new bash instance, then depending on if you want: 

(1) Extremely Basic dependency injected backend (oauth logic in the backend itself)? 
```
python local_setup.py -v backend
```
Open http://localhost:9000/docs
Click the "Authorize" button.
Use the credentials:

User: johndoe

Password: secret

Now use the operation GET with the path /users/me.


(2) JWT Tokens for usuable dependency injected backend  
```
python local_setup.py -v backend2
```

we created a file here called secrets.json, usually you would use env vars or a secret store for this info, NEVER ACTUALLY HAVING THE FILE COMMITTED TO A PUBLIC REPO
we generated that using the command: 
```
openssl rand -hex 32
```

## Multistage Auth 

### Backend 


## Auth 

Next open another bahs instance, then run: 
```
python local_setup.py -v oauth
```

## Frontend

Now open a final bash instance, then run: 
```
python local_setup.py -v frontend
```