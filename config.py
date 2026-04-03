import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY                     = os.getenv("SECRET_KEY", "fallback_secret")
    FLASK_DEBUG                    = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    FLASK_PORT                     = int(os.getenv("FLASK_PORT", 5000))

    # Database — MySQL
    _DB_HOST     = os.getenv("DATABASE_HOST",     "localhost")
    _DB_PORT     = os.getenv("DATABASE_PORT",     "3306")
    _DB_NAME     = os.getenv("DATABASE_NAME",     "pulse")
    _DB_USERNAME = os.getenv("DATABASE_USERNAME", "root")
    _DB_PASSWORD = os.getenv("DATABASE_PASSWORD", "")

    SQLALCHEMY_DATABASE_URI        = f"mysql+pymysql://{_DB_USERNAME}:{_DB_PASSWORD}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT
    JWT_SECRET                     = os.getenv("JWT_SECRET", "fallback_jwt_secret")

    # Monitor account
    MONITOR_USERNAME               = os.getenv("MONITOR_USERNAME", "monitor")
    MONITOR_PASSWORD               = os.getenv("MONITOR_PASSWORD", "monitor123")

    MONITOR_REAL_EMAIL = os.getenv("MONITOR_REAL_EMAIL")
    MONITOR_EMAIL = os.getenv("MONITOR_EMAIL")
    MONITOR_ROLE = os.getenv("MONITOR_ROLE", "admin")
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'Pulse Monitor <no-reply@pulse.app>')

    # App URL
    APP_URL                        = os.getenv("APP_URL", "http://localhost:5000")

    # Mail (SMTP) - XAMPP Mercury Mail on port 25
    MAIL_SERVER   = os.getenv("MAIL_SERVER",   "localhost")
    MAIL_PORT     = int(os.getenv("MAIL_PORT", 25))
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "root")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_SENDER   = os.getenv("MAIL_SENDER",   "test@localhost")
    MAIL_USE_TLS  = False
    MAIL_USE_SSL  = False
    MONITOR_SECRET_PATH = os.getenv("MONITOR_SECRET_PATH", "monitor-admin")
