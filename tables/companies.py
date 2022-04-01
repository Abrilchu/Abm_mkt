from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class CompaniesCreate(BaseModel): # porque son campos que deben existir 
    name : str
    web: str
class Companies(CompaniesCreate): # para hacer update
    company_id:int
    class Config:
        orm_mode = True
class CompaniesModel(Base): # para armar metadata
    __tablename__ = 'companies'
    companies_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    web = Column(String)

