from typing import List, Optional
from sqlmodel import Field, Relationship, SQLModel

class Article(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    quantity: int
    username: Optional[str] = Field(default=None, foreign_key="user.username")
    # user_id: Optional[int] = Field(default=None, foreign_key="user.id")
    user: Optional["User"] = Relationship(back_populates="articles")

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, index=True)
    username: str
    mail: str = Field(unique=True)
    hashed_password: str

    articles: List[Article] = Relationship(back_populates="user")