from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class buyersjourneyCreate(BaseModel):
    name: str
    description: str
class buyersjourney(buyersjourneyCreate):
    bj_id: int
    class Config:
        orm_mode = True
class buyersjourneyModel(Base):
    __tablename__ = 'buyersjourney'
    bj_id = Column(Integer, primary_key=True, index=True) 
    name = Column(String)
    description = Column(String)