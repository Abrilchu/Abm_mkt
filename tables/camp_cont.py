from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer
from app.db import Base

class Camp_contCreate(BaseModel):
    camp_id : int
    cont_id : int
    dc_id : int
class Camp_cont(Camp_contCreate):
    camp_cont_id : int
    class Config:
        orm_mode : True
class Camp_cont_Model(Base):
    __tablename__ = "camp_cont"
    camp_cont_id = Column(Integer, primary_key=True)
    camp_id = Column(Integer)
    cont_id = Column(Integer)
    dc_id = Column(Integer)
