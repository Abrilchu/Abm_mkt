from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class contentCreate(BaseModel):
    cont_type_id: int
    name: str
    description: str
    link: str
class content(contentCreate):
    cont_id: int
    class Config:
        orm_mode = True
class contentModel(Base):
    __tablename__ = 'content'
    cont_id = Column(Integer, primary_key=True, index=True)
    cont_type_id = Column(Integer, ForeignKey('cont_type.cont_type_id', ondelete='CASCADE'))
    name = Column(String)
    description = Column(String)
    link = Column(String)