from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class bc_bpCreate(BaseModel):
    bc_id : int
    bp_id: int
    role_id: int
class bc_bp(bc_bpCreate):
    bc_bp_id:int
    class Config:
        orm_mode = True
class bc_bpModel(Base):
    __tablename__ = 'bc_bp'
    bc_bp_id = Column(Integer, primary_key=True, index=True)
    bp_id = Column(Integer, ForeignKey('buyerpersona.bp_id', ondelete='CASCADE'))
    bc_id = Column(Integer, ForeignKey('buyingcomitee.bc_id', ondelete='CASCADE'))
    role_id = Column(Integer)    
    