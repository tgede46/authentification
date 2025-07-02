from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, APIRouter
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import User

router=APIRouter(
    prefix='/articles',
    tags=['articles']
)

@router.get('/')
async def get_articles():
    pass
