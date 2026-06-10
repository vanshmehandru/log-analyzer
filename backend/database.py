import os
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "security_log_analyzer")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")

# PostgreSQL connection string
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

try:
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    print("Database engine initialized.")
except Exception as e:
    print(f"Failed to initialize database engine: {e}")

Base = declarative_base()

def initialize_database():
    """Verifies that database schema matches current SQLAlchemy models, recreates if mismatch detected."""
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        recreate = False
        for table_name, table in Base.metadata.tables.items():
            if table_name not in existing_tables:
                print(f"Table '{table_name}' does not exist.")
                recreate = True
                break
            
            db_cols = {col["name"] for col in inspector.get_columns(table_name)}
            model_cols = {col.name for col in table.columns if col.name is not None}
            if not model_cols.issubset(db_cols):
                print(f"Schema mismatch detected for table '{table_name}'. Model has {model_cols}, but DB has {db_cols}.")
                recreate = True
                break
        
        if recreate:
            print("Schema mismatch or missing tables. Re-creating all tables...")
            Base.metadata.drop_all(bind=engine)
            Base.metadata.create_all(bind=engine)
            print("Database tables re-created successfully.")
        else:
            print("Database schema is up-to-date.")
            Base.metadata.create_all(bind=engine)
    except Exception as e:
        print(f"Error initializing database tables: {e}")
        # Fallback to standard creation
        try:
            Base.metadata.create_all(bind=engine)
        except Exception as fallback_err:
            print(f"Fallback database initialization failed: {fallback_err}")

def get_db():
    """Dependency to get a database session for requests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

