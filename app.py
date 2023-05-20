from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
import hmac
import hashlib
import struct
import base64
import ggwave
import numpy as np
import io
from scipy.io.wavfile import write
from typing import Optional
import uvicorn
import time
import bcrypt
import random
import string

app = FastAPI()
security = HTTPBearer()

# JWT settings
SECRET_KEY = "your secret key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ggwave_SampleFormat enumeration
GGWAVE_SAMPLE_FORMAT_UNDEFINED = 0
GGWAVE_SAMPLE_FORMAT_U8 = 1
GGWAVE_SAMPLE_FORMAT_I8 = 2
GGWAVE_SAMPLE_FORMAT_U16 = 3
GGWAVE_SAMPLE_FORMAT_I16 = 4
GGWAVE_SAMPLE_FORMAT_F32 = 5

# operating modes enumeration
GGWAVE_OPERATING_MODE_RX = 1 << 1
GGWAVE_OPERATING_MODE_TX = 1 << 2
GGWAVE_OPERATING_MODE_RX_AND_TX = GGWAVE_OPERATING_MODE_RX | GGWAVE_OPERATING_MODE_TX
GGWAVE_OPERATING_MODE_TX_ONLY_TONES = 1 << 3
GGWAVE_OPERATING_MODE_USE_DSS = 1 << 4

# set custom ggwave parameters dictionary
set_parameters = {
    'payloadLength': 8,
    'sampleRateInp': 48000,
    'sampleRateOut': 48000,
    'sampleRate': 48000,
    'samplesPerFrame': 1024,
    'soundMarkerThreshold': 0.1,
    'sampleFormatInp': GGWAVE_SAMPLE_FORMAT_I16,
    'sampleFormatOut': GGWAVE_SAMPLE_FORMAT_I16,
    'operatingMode': GGWAVE_OPERATING_MODE_TX | GGWAVE_OPERATING_MODE_USE_DSS
}

# initialize ggwave with custom parameters
custom_ggwave = ggwave.init(set_parameters)

# User Secret Key
USER_SECRET_KEY = base64.b32encode("yuXyZEt38RlL63epVngI".encode('utf-8')).decode('utf-8')

# Database settings
SQLALCHEMY_DATABASE_URL = 'postgresql://becode2:becode2%404T@localhost:5432/becode2'

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


class Lock(Base):
    __tablename__ = "locks"

    lock_id = Column(String, primary_key=True, index=True)
    lock_sn = Column(String, primary_key=True, index=True)
    secret = Column(String, unique=True)
    counter = Column(Integer)


class LockIn(BaseModel):
    lock_id: str
    lock_sn: str


# Pydantic models
class UserIn(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    username: str


class WaveformModel(BaseModel):
    secret: str
    counter: int


class ValidateModel(BaseModel):
    hotp_code: int


class CounterModel(BaseModel):
    counter: int


# Dependency
def get_db():
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_lock_secret():
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(20))
    encoded_password = base64.b32encode(password.encode('utf-8')).decode('utf-8')
    return encoded_password


def generate_six_digit_number():
    return random.randint(100000, 999999)


# JWT operations
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")

    if not is_token_valid(payload['exp']):
        raise HTTPException(status_code=403, detail="Token Expired")

    return payload['id']


def is_token_valid(exp_claim):
    current_time = int(time.time())  # Get the current Unix timestamp
    return current_time < exp_claim <= current_time + 3600


def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = get_user(db, username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception


def username_exists(username: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    return user is not None


def lock_id_exists(lock_id: str, db: Session):
    lock = db.query(Lock).filter(Lock.lock_id == lock_id).first()
    return lock is not None


def lock_sn_exists(lock_sn: str, db: Session):
    lock = db.query(Lock).filter(Lock.lock_sn == lock_sn).first()
    return lock is not None


def generate_hotp(secret, counter):
    key = base64.b32decode(secret)
    msg = struct.pack('>Q', counter)
    hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hmac_digest[-1] & 0xf
    code = (struct.unpack('>I', hmac_digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000
    return code


def generate_waveform(hotp_code):
    # Use ggwave.encode() to generate the waveform bytes
    waveform_data = ggwave.encode(f'{hotp_code}', protocolId=8, volume=50, instance=custom_ggwave)

    waveform_np = np.frombuffer(waveform_data, dtype=np.int16)

    # Write the NumPy array to a WAV file using scipy.io.wavfile.write
    wav_data = io.BytesIO()
    write(wav_data, 48000, waveform_np)
    wav_data.seek(0)
    return wav_data.read()


@app.post("/locks/add")
def add_lock(lock: LockIn, db: Session = Depends(get_db)):
    if lock_id_exists(lock.lock_id, db):
        raise HTTPException(status_code=409, detail="Lock ID already exists")

    if lock_sn_exists(lock.lock_sn, db):
        raise HTTPException(status_code=409, detail="Lock Serial Number already exists")
    new_lock = Lock(
        lock_id=lock.lock_id,
        lock_sn=lock.lock_sn,
        secret=create_lock_secret(),
        counter=generate_six_digit_number(),
    )

    db.add(new_lock)
    db.commit()
    db.refresh(new_lock)
    return {"message": "Lock has been added successfully"}


@app.post("/users/create")
def create_user(user: UserIn, db: Session = Depends(get_db)):
    if username_exists(user.username, db):
        raise HTTPException(status_code=409, detail="Username already exists")

    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    hashed_password = hashed_password.decode('utf8')
    new_user = User(
        username=user.username,
        hashed_password=hashed_password,
        counter=0,
        secret=USER_SECRET_KEY
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}


@app.post("/token")
def login_for_access_token(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=401,
                            detail="Invalid username or password",
                            headers={"WWW-Authenticate": "Bearer"}
                            )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"id": user.id, "username": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/generate/code/new/{lock_sn}")
def generate_new_code(lock_sn, token_validated: bool = Depends(validate_token), db: Session = Depends(get_db)):
    user_id = token_validated
    lock = db.query(Lock).filter(Lock.lock_sn == lock_sn).first()
    lock.counter += 1
    db.commit()

    code = str(generate_hotp(lock.secret, lock.counter))

    return {"hotp_code": code, "counter": lock.counter}


@app.post("/generate/code/old/{lock_sn}")
def generate_old_code(lock_sn, token_validated: bool = Depends(validate_token), db: Session = Depends(get_db)):
    user_id = token_validated
    lock = db.query(Lock).filter(Lock.lock_sn == lock_sn).first()

    code = str(generate_hotp(lock.secret, lock.counter))

    return {"hotp_code": code, "counter": lock.counter}


@app.post("/generate/soundwave/{hotp_code}")
async def generate_soundwave(hotp_code, token_validated: bool = Depends(validate_token), db: Session = Depends(get_db)):
    waveform_data = generate_waveform(hotp_code)
    # Returns the audio data as a file response
    return StreamingResponse(io.BytesIO(waveform_data), media_type='audio/wav')


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# ----------- Previous endpoints ----------- #
def verify_hotp(secret, hotp_code, counter, lookahead=9):
    for i in range(0, lookahead):
        if generate_hotp(secret, counter + i) == hotp_code:
            return True, counter + i + 1
    return False, counter


@app.get("/counterr", response_model=UserOut)
async def get_counter(current_user: User = Depends(get_current_user)):
    # return the current user's counter
    return {"username": current_user.username, "counter": current_user.counter, "secret": current_user.secret}


@app.post("/counterr", response_model=UserOut)
async def reset_counter(new_counter: int, db: Session = Depends(get_db),
                        current_user: User = Depends(get_current_user)):
    # Update counter value
    if new_counter < 0:
        raise HTTPException(status_code=400, detail="Counter must be a positive number")
    current_user.counter = new_counter
    db.commit()
    return {"username": current_user.username, "counter": current_user.counter, "secret": current_user.secret}


# ----------- UVICORN SERVER ----------- #
if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    uvicorn.run(app, host="127.0.0.1", port=2000)
