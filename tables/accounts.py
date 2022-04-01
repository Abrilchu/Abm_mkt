from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class accountsCreate(BaseModel):
    icp_tier_id: int
    name: str
    website: str
    linkedin: str
    country_id: int
    city: str
    employ_num: int
    anual_revenue: int
    stg_id: int
class accounts(accountsCreate):
    account_id : int
    class Config:
        orm_mode = True
class accountsModel(Base):
    __tablename__ = 'accounts'
    account_id = Column(Integer, primary_key=True, index=True)
    icp_tier_id = Column(Integer, ForeignKey('icp_tier.icp_tier_id', ondelete='CASCADE'))
    name = Column(String)
    website = Column(String)
    linkedin = Column(String)
    country_id = Column(Integer, ForeignKey('country.country_id', ondelete='CASCADE'))
    city = Column(String)
    employ_num = Column(Integer)
    anual_revenue = Column(Integer)
    stg_id = Column(Integer, ForeignKey('stages.stg_id', ondelete='CASCADE'))