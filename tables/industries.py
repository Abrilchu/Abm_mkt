from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer
from app.db import Base

class IndustriesCreate(BaseModel):
    name: str
    description: str

class Industries(IndustriesCreate):
    id: int
    class Config:
        orm_mode = True

class IndustriesModel(Base):
    __tablename__ = 'industries'
    id = Column(Integer, primary_key=True, index=True)
    name= Column(String)
    description= Column(String)
