from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, APIRouter
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt



router=APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"


bcrypt_context= CryptContext( schemes=['bcrypt'], deprecated='auto')
oauth2_bearer=OAuth2PasswordBearer(tokenUrl='auth/Token')

class  CreateUserRequest(BaseModel):
    username: str
    mail: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    username: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependancy=Annotated[Session,Depends(get_db)]

@router.post('/register', status_code=status.HTTP_201_CREATED)
async def create_user(db:db_dependancy,create_user_request:CreateUserRequest):
    create_user_model=User(
        username=create_user_request.username,
        mail=create_user_request.mail,
        hashed_password=bcrypt_context.hash(create_user_request.password)
    )

    db.add(create_user_model)
    db.commit()
    return {'username':create_user_model.username,
            'mail':create_user_model.mail,
            'password':create_user_model.hashed_password}

@router.post('/login', response_model=Token)
async def login_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                             db: db_dependancy):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='erreur nom d utilisateur'
        )
    token = create_user_token(user.username, user.id, timedelta(minutes=25))
    return Token(access_token=token, token_type='bearer')



def authenticate_user(username: str, password: str, db):
    user=db.query(User).filter(User.username==username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password,user.hashed_password):
        return False
    return user 
   

def create_user_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expire = datetime.utcnow() + expires_delta
    encode.update({'exp': expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

@router.post('/forgot-password', response_model=Token)
async def forgot_password(forgot_request: ForgotPasswordRequest, db: db_dependancy):
    user = authenticate_forgot_password(forgot_request.username, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='utilisateur non trouvé'
        )
    # mon probleme est ici
    token = create_user_token(user.username, user.id, timedelta(minutes=15))
    return Token(access_token=token, token_type='bearer')

def authenticate_forgot_password(username:str,db):
    user=db.query(User).filter(User.username==username).first()
    if not user:
        return None
    return user
    
@router.post('/reset-password')
async def reset_password(reset_request: ResetPasswordRequest, db: db_dependancy):
    try:
        payload = jwt.decode(reset_request.token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='token invalide'
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='token invalide'
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='utilisateur non trouvé'
        )
    user.hashed_password = bcrypt_context.hash(reset_request.new_password)
    db.commit()
    
    return {'message': 'mot de passe réinitialisé avec succès'}


