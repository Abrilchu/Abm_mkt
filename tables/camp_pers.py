from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class camp_persCreate(BaseModel):
    persona_id: int
    camp_id: int
class camp_pers(camp_persCreate):
    camp_pers_id: int
    class Config:
        orm_mode = True
class camp_persModel(Base):
    __tablename__ = 'camp_pers'
    camp_pers_id = Column(Integer, primary_key=True, index=True)
    persona_id = Column(Integer, ForeignKey('personas.persona_id', ondelete='CASCADE'))
    camp_id = Column(Integer, ForeignKey('campaign.camp_id', ondelete='CASCADE'))