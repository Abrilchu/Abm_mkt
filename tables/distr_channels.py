from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class distr_channelsCreate(BaseModel):
    name: str
    description: str
    tool: str
class distr_channels(distr_channelsCreate):
    dc_id: int
    class Config:
        orm_mode = True
class distr_channelsModel(Base):
    __tablename__ = 'distr_channels'
    dc_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)
    tool = Column(String)