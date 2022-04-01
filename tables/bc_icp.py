from pydantic import BaseModel
from sqlalchemy import Column, ForeignKey, String, Float, Integer
from app.db import Base

class Bc_icpCreate(BaseModel):
    icp_id : int
    bc_id : int
class Bc_icp(Bc_icpCreate):
    bc_icp_id : int
    class Config:
        orm_mode = True
class Bc_icp_Model(Base):
    __tablename__ = 'bc_icp'
    bc_icp_id = Column(Integer, primary_key=True, index=True)
    icp_id = Column(Integer, ForeignKey('icp.icp_id', ondelete='CASCADE'))
    bc_id = Column(Integer, ForeignKey('buyingcomitee.bc_id', ondelete='CASCADE'))
    