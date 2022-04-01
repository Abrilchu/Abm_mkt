from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


    # engine = create_engine("postgresql://postgres:@localhost:5432/postgres")
SQL_DATABASE_URL = "postgresql://postgres:Abrilb30!@localhost:5432/Security"

engine = create_engine(
    SQL_DATABASE_URL
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()