"""
Pulse — Intentionally Vulnerable Flask Social Media App
OWASP A01: Broken Access Control Training Platform

⚠️  FOR EDUCATIONAL USE ONLY — NEVER DEPLOY IN PRODUCTION ⚠️
"""

import os
import pymysql
from flask import Flask
from config import Config
from werkzeug.security import generate_password_hash

from models import User
from extensions import db, socketio, mail

from helpers import send_account_email


# ── Blueprints ──────────────────────────────
from routes.auth     import auth
from routes.feed     import feed
from routes.profile  import profile
from routes.messages import messages
from routes.api      import api
from routes.admin    import admin
from routes.account  import account
from routes.social   import social
from routes.extra    import extra
from routes.features import features
from monitor.routes  import monitor




def ensure_database_exists():
    """Create the MySQL database if it doesn't exist yet."""
    conn = pymysql.connect(
        host=os.getenv("DATABASE_HOST", "localhost"),
        port=int(os.getenv("DATABASE_PORT", 3306)),
        user=os.getenv("DATABASE_USERNAME", "root"),
        password=os.getenv("DATABASE_PASSWORD", ""),
    )
    with conn.cursor() as cursor:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{os.getenv('DATABASE_NAME', 'pulse')}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        )
    conn.commit()
    conn.close()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["JWT_SECRET"] = Config.JWT_SECRET

    ensure_database_exists()

    db.init_app(app)
    socketio.init_app(app)
    mail.init_app(app)

    # ── Register blueprints ──────────────────
    # app.register_blueprint(auth)
    # app.register_blueprint(feed)
    # app.register_blueprint(profile)
    # app.register_blueprint(messages)
    # app.register_blueprint(api)
    # app.register_blueprint(admin)
    # app.register_blueprint(account)
    # app.register_blueprint(social)
    # app.register_blueprint(extra)
    # app.register_blueprint(features)
    # app.register_blueprint(monitor)

    # ── Register blueprints ──────────────────
    blueprints = [auth, feed, profile, messages, api, admin, account, social, extra, features, monitor]
    for bp in blueprints:
        app.register_blueprint(bp)

    # ── Context processor ────────────────────
    # Injects monitor_secret into every template.
    # Only renders in layout.html when user.role == "admin",
    # so participants never see the URL even in page source.
    @app.context_processor
    def inject_monitor_secret():
        return {"monitor_secret": Config.MONITOR_SECRET_PATH}

    # ── DB init & seed ───────────────────────
    with app.app_context():
        db.create_all()
        seed_db()

    return app


from werkzeug.security import generate_password_hash

def seed_db():
    """Create only the monitor/instructor account on first run."""

    existing = User.query.filter_by(username=Config.MONITOR_USERNAME).first()
    if existing:
        return

    raw_password = Config.MONITOR_PASSWORD
    hash_password = generate_password_hash(raw_password)

    print("\nCreating monitor account...")
    print("Password hashed successfully")

    monitor_user = User(
        username=Config.MONITOR_USERNAME,
        password=hash_password,
        email=Config.MONITOR_REAL_EMAIL,
        platform_email=Config.MONITOR_EMAIL,
        display_name="Monitor",
        role=Config.MONITOR_ROLE,
        verified=True,
        bio="Instructor monitoring account."
    )
    
    db.session.add(monitor_user)
    db.session.commit()

    # 🔥 SEND EMAIL AFTER CREATION
    send_account_email(
        to_email=Config.MONITOR_REAL_EMAIL,
        username=Config.MONITOR_USERNAME,
        password=raw_password  # ⚠️ acceptable for lab, not production
    )

    print("📧 Monitor email sent successfully")
    print(f"✅ Monitor account created → username: {Config.MONITOR_USERNAME}")



if __name__ == "__main__":
    app = create_app()

    print(f"DEBUG: app = {app}")
    socketio.run(app, debug=Config.FLASK_DEBUG, port=Config.FLASK_PORT)

