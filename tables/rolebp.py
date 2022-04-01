from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class RolebpCreate(BaseModel):
    name: str
    description: str
class Role_bp(RolebpCreate):
    role_id:int
    class Config:
        orm_mode = True
class Role_bpModel(Base):
    __tablename__ = 'Role_bp'
    role_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)    