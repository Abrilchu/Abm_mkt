from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class IcpCreate(BaseModel):
    name : str
    servprodcomp_id : int
    employ_num_i : int 
    employ_num_f : int
    country_id : int
    anual_reve_i : int 
    anual_reve_f : int
    notes : str
class Icp(IcpCreate):
    icp_id : int 
    class Config:
        orm_mode = True
class Icp_Model(Base):
    __tablename__ = 'icp'
    icp_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    servprodcomp_id : Column(Integer, ForeignKey('servprodcomp.servprodcomp_id', ondelete='CASCADE'))
    employ_num_i : Column(Integer)
    employ_num_f : Column(Integer)
    country_id : Column(Integer, ForeignKey('country.country_id', ondelete='CASCADE'))
    anual_reve_i : Column(Integer)
    anual_reve_f : Column(Integer)
    notes : Column(String)

    
