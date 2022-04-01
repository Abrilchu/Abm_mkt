import email
from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class personasCreate(BaseModel):
    first_name: str
    last_name: str
    account_id: int
    jobtitle_id: int
    email: str
    linkedin: str
    country: str
class personas(personasCreate):
    persona_id: int
    class Config:
        orm_mode = True
class personasModel(Base):
    __tablename__ = 'personas'
    persona_id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    account_id = Column(Integer)
    jobtitle_id = Column(Integer, ForeignKey('jobtitle.jobtitle_id', ondelete='CASCADE'))
    email = Column(String)
    linkedin = Column(String)
    country = Column(String)