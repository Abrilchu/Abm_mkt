from MySQLdb import Date
from sqlalchemy import Column, Boolean, Integer, String, DateTime
from .databaseMKT import Base

class Users(Base):
    __tablename__ = "users_auth"
    usr_id = Column(Integer, primary_key=True)
    usr_login = Column(String)
    usr_alias = Column(String)
    usr_password = Column(String)
    usr_enabled = Column(Boolean)
    usr_creation_date = Column(DateTime)
    usr_auth_reaim = Column(String)