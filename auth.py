from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, APIRouter
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import User, Article
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt



router=APIRouter(
    
)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"


bcrypt_context= CryptContext( schemes=['bcrypt'], deprecated='auto')
oauth2_bearer=OAuth2PasswordBearer(tokenUrl='auth/Token')

# parti de au authentification
class  CreateUserRequest(BaseModel):
    username: str
    mail: EmailStr
    password: str

class ForgotPasswordRequest(BaseModel):
    mail: str
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
class Token(BaseModel):
    access_token: str
    token_type: str
    

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

# parti des articles
class CreateArticleRequest(BaseModel):
    title:str
    quantity:int
    username:str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependancy=Annotated[Session,Depends(get_db)]

@router.post('/register', status_code=status.HTTP_201_CREATED,tags=['auth'])
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

@router.post('/login', response_model=TokenResponse, tags=['auth'])
async def login_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                             db: db_dependancy):
    user = db.query(User).filter(User.mail == form_data.username).first()
    if not user or not bcrypt_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='erreur mail ou mot de passe'
        )
    access_token = create_user_token(user.username, user.id, timedelta(minutes=25))
    refresh_token = create_refresh_token(user.username, user.id, timedelta(days=7))
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type='bearer'
    )


class RefreshTokenRequest(BaseModel):
    refresh_token: str

@router.post('/refresh', response_model=Token)
async def refresh_access_token(refresh_request: RefreshTokenRequest, db: db_dependancy):
    try:
        payload = jwt.decode(refresh_request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='refresh token invalide'
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='refresh token invalide'
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='utilisateur non trouvé'
        )
    access_token = create_user_token(user.username, user.id, timedelta(minutes=25))
    return Token(access_token=access_token, token_type='bearer')


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


def create_refresh_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expire = datetime.utcnow() + expires_delta
    encode.update({'exp': expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


@router.post('/forgot-password', response_model=Token, tags=['auth'])
async def forgot_password(forgot_request: ForgotPasswordRequest, db: db_dependancy):
    user = authenticate_forgot_password(forgot_request.mail, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='utilisateur non trouvé'
        )
    token = create_user_token(user.mail, user.id, timedelta(minutes=15))
    return Token(access_token=token, token_type='bearer')

def authenticate_forgot_password(mail: str, db):
    user = db.query(User).filter(User.mail == mail).first()
    if not user:
        return None
    return user
    
@router.post('/reset-password',tags=['auth'])
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


@router.post('/', tags=['article'], status_code=status.HTTP_201_CREATED)
async def create_article(db: db_dependancy, create_article_request: CreateArticleRequest):
    # Vérifier que l'utilisateur existe
    user = db.query(User).filter(User.username == create_article_request.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    article_model = Article(
        title=create_article_request.title,
        quantity=create_article_request.quantity,
        username=create_article_request.username  
    )
    db.add(article_model)
    db.commit()
    return {
        'title': article_model.title,
        'quantity': article_model.quantity,
        'username': article_model.username
    }

@router.get('/',tags=['article'])
async def get_articles(db:db_dependancy):
    articles=db.query(Article).all()
    if not articles:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='aucun article trouvé'
        )
    return articles

@router.get('/{article_id}',tags=['article'])
async def get_article(article_id: int, db: db_dependancy):
    article = db.query(Article).filter(Article.id == article_id).first()
    if not article:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='article non trouvé'
        )
    return article


@router.delete('/{article_id}',tags=['article'])
async def delete_article(article_id: int, db: db_dependancy):
    article = db.query(Article).filter(Article.id == article_id).first()
    if not article:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='article non trouvé'
        )
    db.delete(article)
    db.commit()
    return {'message': 'article supprimé avec succès'}

@router.put('/{article_id}',tags=['article'])
async def update_article(article_id: int, create_article_request: CreateArticleRequest, db: db_dependancy):
    article = db.query(Article).filter(Article.id == article_id).first()
    if not article:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='article non trouvé'
        )
    user = db.query(User).filter(User.username == create_article_request.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé"
        )
    
    article.title = create_article_request.title
    article.quantity = create_article_request.quantity
    article.username = create_article_request.username
    
    db.commit()
    return {
        'title': article.title,
        'quantity': article.quantity,
        'username': article.username
    }

@router.get('/user/{username}', tags=['article'])
async def get_user_articles(username: str, db: db_dependancy):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='utilisateur non trouvé'
        )
    articles = db.query(Article).filter(Article.username == username).all()
    if not articles:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='aucun article trouvé pour cet utilisateur'
        )
    return articles