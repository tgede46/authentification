from typing import List, Optional
from pydantic import Field
from sqlmodel import Relationship
from database import Base
from sqlalchemy import Column, Integer, String


class User(Base):
    __tablename__='user'

    id = Column(Integer, primary_key=True, index= True)
    username=Column(String,unique=True)
    mail=Column(String,unique=True)
    hashed_password=Column(String)

#     articles: List["Article"] = Relationship(back_populates="user")
#     def __repr__(self) -> str:
#         return f"user:{self.username}"

# class Article(Base):
#     __tablename__='article'
    
#     id=Column(Integer, primary_key=True, index= True)
#     title:str 
#     quantity:int
#     username: str = Field(foreign_key="user.username")


#     user: Optional[User] = Relationship(back_populates="articles")
