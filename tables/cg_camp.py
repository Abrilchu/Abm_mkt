from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer
from app.db import Base

class Cg_campCreate(BaseModel):
    cg_id : int
    camp_id : int
class Cg_camp(Cg_campCreate):
    cg_camp_id : int
    class Config:
        orm_mode : True
class Cg_camp_Model(Base):
    __tablename__ = "cg_camp"
    cg_camp_id = Column(Integer, primary_key=True)
    cg_id = Column(Integer)
    camp_id = Column(Integer)