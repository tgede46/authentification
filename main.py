from fastapi import FastAPI, status,Depends,HTTPException
from sqlmodel import SQLModel
import models
from database import engine, SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
import auth


app=FastAPI()
app.include_router(auth.router)

SQLModel.metadata.create_all(bind=engine)


def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependancy=Annotated[Session, Depends(get_db)]
