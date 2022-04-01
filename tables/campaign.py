from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer
from app.db import Base

class CampaignCreate(BaseModel):
    name: str
    description:str 
    date_start:str
    date_end:str
class Campaign(CampaignCreate):
    camp_id:int
    class Config:
        orm_mode = True
class CampaignModel(Base):
    __tablename__ = 'campaign'
    camp_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)     
    date_start = Column(String)
    date_end = Column(String)
