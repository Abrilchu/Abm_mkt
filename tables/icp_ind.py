from pydantic import BaseModel
from sqlalchemy import Column, ForeignKey, String, Integer
from app.db import Base

class Icp_indCreate(BaseModel):
    ind_id : int
    icp_id : int 
class Icp_ind(Icp_indCreate):
    icp_ind_id : int 
    class Config:
        orm_mode = True
class Icp_ind_Model(Base):
    __tablename__ = 'icp_ind'
    icp_ind_id = Column(Integer, primary_key=True, index=True)
    ind_id = Column(Integer, ForeignKey('industries.ind_id', ondelete='CASCADE'))
    icp_id = Column(Integer, ForeignKey('icp.icp_id', ondelete='CASCADE'))