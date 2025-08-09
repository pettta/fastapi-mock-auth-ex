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