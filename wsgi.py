# from app import create_app, socketio

# app = create_app()

# if __name__ == "__main__":
#     socketio.run(app)

"""
WSGI entry point for Gunicorn (Production)
Pulse Flask Application
"""

import os
from app import create_app
from extensions import socketio
from config import Config

# Create Flask app using factory pattern
app = create_app()


# Optional: seed DB on first boot (safe guard)
with app.app_context():
    try:
        from app import seed_db
        seed_db()
    except Exception as e:
        print(f"Seed skipped or failed: {e}")


# Attach SocketIO to app (IMPORTANT for Gunicorn + Nginx + WebSockets)
socketio.init_app(app)


# Gunicorn entrypoint
if __name__ == "__main__":
    # Dev only (NOT used in production)
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", Config.FLASK_PORT)),
        debug=Config.FLASK_DEBUG
    )