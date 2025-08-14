from fastapi import FastAPI

app = FastAPI()

# TODO (1) 
# HAVE BASIC ENDPOINTS, GET AUTHORIZE(code_challenge, hashing algorithm, redirect URI)->one_time_code POST LOGIN(one_time_code), POST CREATE_ACCOUNT(one_time_code), AND POST TOKEN(code_verifier)
# DONT BOTHER WITH THE LOGIC YET


# TODO (2) 
# IMPLEMENT A SIMILAR TOKEN VERIFIER TO WHAT WE HAVE IN BACKEND 4 
# HAVE IT SUPPORT MULTIPLE DIFFERENT AUTH PROVIDERS DEPENDING ON THE ARGS PASSED INTO THIS API 
# IT WILL HAVE A DIFFERENT CLIENT FOR EACH OF THE EXTERNAL LOGINS WE WANT TO USE 


# TODO (3) 
# IMPLEMENT A TABLE THAT MAPS THE SUBJECT OF THE DECOCDED JWT TO OUR INTERNAL AUTHORIZATION LOGIC
# USER FIELDS: internal_id: UUID, internal_refresh_token: str, google_id: str, microsoft_id: str, last_login: datetime, disabled: bool


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


# TODO (5) Actually do the logic for the GET /auth
# 1. Extract the code_challenge and code_challenge_method from the request query parameters
# 2. create a one_time_code that is random and unique(and runs out in 5m if its login, 30m if its register), verify its not already in use, 
    # and in the global dict AUTH_REQUEST_TABLE[one_time_code] store the (code_challenge, code_challenge_method, disabled=true)
# 3. Redirect the user to the redirect URI (which is either the login or register endpoint, depending on the button the user clicked)


# TODO (6) Actually do the logic for POST /login
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


# TODO (6) Actually do the logic for POST /token
# 1a. Check if we have a one time code in the request body
# 2a. If we do, look up the AUTH_REQUEST_TABLE[one_time_code] entry, see if (a) it exists, (b) is enabled, and (c) is not expired (d) the hash of the code verifier = the code challenge
# 3a. If all those passed, generate a new 7 day refresh token to this user's database table, have it generate a JWT, return those as http-only cookies in the response
# 1b. Check if we have a JWT & Refresh token in the request body: 
# 2b: JWT & refresh not expired = do nothing 
# 3b: JWT expired = create new refresh token, then use that to create a new JWT (refresh token rotation)
# 4b: Refresh token expired = Error out the user --> frontend will give error message that tells them to relog in 