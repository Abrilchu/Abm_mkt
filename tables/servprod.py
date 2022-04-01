from pydantic import BaseModel
from sqlalchemy import Column, String, Integer
from app.db import Base

class ServprodCreate(BaseModel):
    name: str
    description: str

class Servprod(ServprodCreate):
    id: int
    class Config:
        orm_mode = True

class ServprodModel(Base):
    __tablename__ = 'serv_prod'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)
