from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer
from app.db import Base

class KPICreate(BaseModel):
    name: str
    value: float
class KPI(KPICreate):
    kpi_id:int
    class Config:
        orm_mode = True
class KPIModel(Base):
    __tablename__ = 'kpi'
    kpi_id = Column(Integer, primary_key=True, index=True)
    #PrimaryKeyConstraint('kpi_id', 'version_id', name='mytable_pk')
    name = Column(String)
    value = Column(Float)
