from inspect import CO_ASYNC_GENERATOR
from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class icp_tierCreate(BaseModel):
    icp_id: int
    tier_id: int
    bc_id: int
class icp_tier(icp_tierCreate):
    icp_tier_id: int
    class Config:
        orm_mode = True
class icp_tierModel(Base):
    __tablename__ = 'icp_tier'
    icp_tier_id = Column(Integer, primary_key=True, index=True)
    icp_id = Column(Integer, ForeignKey('icp.icp_id', ondelete='CASCADE'))
    tier_id = Column(Integer, ForeignKey('tiers.tier_id', ondelete='CASCADE'))
    bc_id = Column(Integer, ForeignKey('buyingcomitee.bc_id', ondelete='CASCADE'))