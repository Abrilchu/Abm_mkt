from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class stagesCreate(BaseModel):
    name: str
    description: str
class stages(stagesCreate):
    stg_id : int
    class Config:
        orm_mode = True
class stagesModel(Base):
    __tablename__ = 'stages'
    stg_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)