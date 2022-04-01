from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer
from app.db import Base

class Campaign_goalsCreate(BaseModel):
    name: str
    description: str
class Campaign_goals(Campaign_goalsCreate):
    cg_id: int
    class Config:
        orm_mode = True
class Campaign_goals_Model(Base):
    __tablename__ = 'campaign_goals'
    cg_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)
    # Podriamos hacer que las descripciones sean opcionales en algunos campos.
    