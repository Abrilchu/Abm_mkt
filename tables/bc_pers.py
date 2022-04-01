from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class bc_persCreate(BaseModel):
    bc_id: int
    role_id: int
    persona_id: int
class bc_pers(bc_persCreate):
    bc_pers__id : int
    class Config:
        orm_mode = True
class bc_persModel(Base):
    __tablename__ = 'bc_pers'
    bc_pers_id = Column(Integer, primary_key=True, index=True)
    bc_id = Column(Integer, ForeignKey('buyingcomitee.bc_id', ondelete='CASCADE'))
    role_id = Column(Integer, ForeignKey('rolebp.role_id', ondelete='CASCADE'))
    persona_id = Column(Integer, ForeignKey('personas.persona_id', ondelete='CASCADE'))