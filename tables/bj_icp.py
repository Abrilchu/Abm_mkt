from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class bj_icpCreate(BaseModel):
    icp_tier_id: int
    bj_id: int
    stg_id: int
    cont_id: int
    dc_id: int
class bj_icp(bj_icpCreate):
    bj_icp_id : int
    class Config:
        orm_mode = True
class bj_icpModel(Base):
    __tablename__ = 'bj_icp'
    bj_icp_id = Column(Integer, primary_key=True)
    icp_tier_id = Column(Integer, ForeignKey('icp_tier.icp_tier_id', ondelete='CASCADE'))
    bj_id = Column(Integer, ForeignKey('buyersjourney.bj_id', ondelete='CASCADE')) 
    stg_id = Column(Integer, ForeignKey('stages.stg_id', ondelete='CASCADE'))
    cont_id = Column(Integer, ForeignKey('content.cont_id', ondelete='CASCADE'))
    dc_id = Column(Integer, ForeignKey('distr_channels.dc_id', ondelete='CASCADE'))