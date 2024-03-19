from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import  jwt, JWTError
from datetime import datetime, timedelta
import time
app = FastAPI()

# Secret key for encoding/decoding JWT tokens
SECRET_KEY = "your_secret_key"
# Algorithm used for encoding/decoding JWT tokens    
ALGORITHM = "HS256"
# Token expiration time in minutes
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# User database (for demonstration purposes)
fake_users_db = {}

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Token generator function
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# User model for signup
class User(BaseModel):
    username: str
    password: str

def decode_token(token):
    decoded_data = jwt.decode(token=token,key=SECRET_KEY, algorithms=ALGORITHM)
    return decoded_data
# User signup route with access token
@app.post("/signup")
def signup(user: User):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = pwd_context.hash(user.password)
    fake_users_db[user.username] = {"username": user.username, "password": hashed_password}
    
    # Create access token for the new user
    access_token = create_access_token({"sub": user.username})
    return {"message": "User registered successfully", "access_token": access_token, "token_type": "bearer"}

  
  
# User login route
@app.post("/login")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token({"sub": user["username"]})
    print(decode_token(access_token))

    return {"access_token": access_token, "token_type": "bearer"}
 


# valid function Decode function to verify and decode JWT token
def decode_function(token: str):
    try:
        decoded_data = jwt.decode(token=token, key=SECRET_KEY, algorithms=["HS256"])
        exp = decoded_data.get('exp')
        epoch_time = int(time.time() - 1800)
        if exp >= epoch_time:
            return decoded_data
        else:
            return "token_expired"
    except JWTError:
        return "invalid_token"

@app.post('/getSomething')
def get_something(token: str, decoded_data: dict = Depends(decode_function)):
    if isinstance(decoded_data, str):
        if decoded_data.lower() == "invalid_token":
            return {"error": "invalid_token"}
        else:
            return {"error": "token_expired"}
    else:
        username = decoded_data.get('sub')
        # do something with username
        return {"message": "Data retrieved successfully for user: " + username}

@app.post("/sample-login")
def sample_login_page():
    return 
   

      