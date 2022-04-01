from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer
from app.db import Base

class BayerpersonaCreate(BaseModel):
    joib_title: str
    objective_goals: str
    paint_points: str
    message: str
    objetions: str
    talking_points: str
    
class Bayerpersona(BayerpersonaCreate):
    id: int
    class Config:
        orm_mode = True

class BayerpersonaModel(Base):
    __tablename__ = 'bayer_personal'
    id = Column(Integer, primary_key=True, index=True)
    joib_title = Column(String)
    objective_goals = Column(String)
    paint_points = Column(String)
    message =Column(String)
    objetions =Column(String)
    talking_points =Column(String)
