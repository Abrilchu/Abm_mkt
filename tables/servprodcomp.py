from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class Servprodcomp_Create(BaseModel): # porque son campos que deben existir 
    sp_id : int
    company_id: int
class Servprodcomp(Servprodcomp_Create): # para hacer update
    servprodcomp_id:int
    class Config:
        orm_mode = True
class ServprodcompModel(Base): # para armar metadata
    __tablename__ = 'servprodcomp'
    servprodcomp_id = Column(Integer, primary_key=True, index=True)
    sp_id = Column(Integer, ForeignKey('servprod.sp_id', ondelete='CASCADE'))
    company_id = Column(Integer, ForeignKey('companies.company_id', ondelete='CASCADE')) # onupdate