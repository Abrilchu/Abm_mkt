from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class buyingcomiteeCreate(BaseModel):
    name: int
    description: int
class buyingcomitee(buyingcomiteeCreate):
    bc_id : int
    class Config:
        orm_mode = True
class buyingcomiteeModel(Base):
    __tablename__ = 'buyingcomitee'
    bc_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)