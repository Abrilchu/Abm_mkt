from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class jobtitleCreate(BaseModel):
    name: str
    description: str
class jobtitle(jobtitleCreate):
    jobtitle_id : int
    class Config:
        orm_mode = True
class jobtitleModel(Base):
    __tablename__ = 'jobtitle'
    jobtitle_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)