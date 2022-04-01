from pydantic import BaseModel
from sqlalchemy import Column, String, Float, Integer, ForeignKey
from app.db import Base

class cont_typeCreate(BaseModel):
    name: str
    description: str
class cont_type(cont_typeCreate):
    cont_type_id: int
    class Config:
        orm_mode = True
class cont_typeModel(Base):
    __tablename__ = 'cont_type'
    cont_type_id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)