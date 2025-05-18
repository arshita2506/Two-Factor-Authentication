import os

class Config:
    # Flask secret key (used for sessions, forms, etc.)
    SECRET_KEY = os.environ.get("SECRET_KEY") or "your_flask_secret_key_here"

    # JWT secret key (used to sign and verify JWT tokens)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "your_jwt_secret_key_here"

    # PostgreSQL database URI format:
    # postgresql://username:password@localhost/databasename
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "postgresql://postgres:arshita123@localhost:5432/init_db"

    # Optional: Turn off SQLAlchemy warning
    SQLALCHEMY_TRACK_MODIFICATIONS = False
