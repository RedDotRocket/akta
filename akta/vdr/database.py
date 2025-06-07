from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from akta.logging import get_logger

logger = get_logger(__name__)

SQLALCHEMY_DATABASE_URL = "sqlite:///./vdr.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency to get a DB session for FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    """Creates all database tables defined by models inheriting from Base."""
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database tables created (if they didn't exist) at {SQLALCHEMY_DATABASE_URL}")
