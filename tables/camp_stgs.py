from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class Camp_stgsCreate(BaseModel):
    stg_id : int
    camp_id: int
class Camp_stgs(Camp_stgsCreate):
    camp_stgs_id:int
    class Config:
        orm_mode = True
class Camp_stgs_Model(Base):
    __tablename__ = 'camp_stgs'
    camp_stgs_id = Column(Integer, primary_key=True, index=True)
    stg_id = Column(Integer)
    camp_id = Column(Integer)    
    kpi_id = Column(Integer, ForeignKey('stages.stg_id', ondelete='CASCADE'))