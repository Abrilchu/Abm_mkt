from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class Camp_KPICreate(BaseModel): # porque son campos que deben existir 
    kpi_id : int
    objective: int
    result: int
class Camp_KPI(Camp_KPICreate): # para hacer update
    camp_kpi_id:int
    class Config:
        orm_mode = True
class Camp_KPIModel(Base): # para armar metadata
    __tablename__ = 'camp_kpi'
    camp_kpi_id = Column(Integer, primary_key=True, index=True)
    objective = Column(Integer)
    result = Column(Integer)    
    kpi_id = Column(Integer, ForeignKey('kpi.kpi_id', ondelete='CASCADE')) # onupdate