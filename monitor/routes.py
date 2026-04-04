import random
import string
import smtplib
import os
import json
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session, abort
from extensions import db, socketio
from models import User, ExploitLog
from helpers import current_user, send_participant_account
from config import Config

# ─────────────────────────────────────────────────────────
#  Secret URL prefix — loaded from .env
#  Participants never see this path — they get a 404
# ─────────────────────────────────────────────────────────
_SECRET           = Config.MONITOR_SECRET_PATH
CREDENTIALS_FILE  = os.path.join(os.path.dirname(__file__), "..", "credentials_log.txt")

monitor = Blueprint("monitor", __name__, url_prefix=f"/{_SECRET}")


# ─── Auth guard ──────────────────────────────────────────

def monitor_required(f):
    """Abort 404 for anyone who is not a logged-in admin.
    A 404 hides the route entirely — no hint it even exists."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            abort(404)
        me = current_user()
        if not me or me.role != "admin":
            abort(404)
        return f(*args, **kwargs)
    return decorated


# ─── Helpers ─────────────────────────────────────────────

def generate_password(length=10):
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choices(chars, k=length))


def generate_platform_email(username):
    return f"{username}@pulse.app"


def save_credentials_to_file(display_name, username, password, platform_email, real_email):
    """Fallback: write credentials to credentials_log.txt."""
    try:
        line = (
            f"\n{'─' * 52}\n"
            f"  Created    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Name       : {display_name}\n"
            f"  Username   : {username}\n"
            f"  Password   : {password}\n"
            f"  Platform   : {platform_email}\n"
            f"  Real Email : {real_email}\n"
            f"  Login URL  : {Config.APP_URL}/login\n"
            f"{'─' * 52}\n"
        )
        with open(CREDENTIALS_FILE, "a", encoding="utf-8") as f:
            f.write(line)
        return True, None
    except Exception as e:
        return False, str(e)


def log_credentials_to_console(display_name, username, password, platform_email, real_email):
    """Last resort: always print to terminal."""
    print("\n" + "═" * 52)
    print("  NEW PARTICIPANT CREDENTIALS")
    print("═" * 52)
    print(f"  Name       : {display_name}")
    print(f"  Username   : {username}")
    print(f"  Password   : {password}")
    print(f"  Platform   : {platform_email}")
    print(f"  Real Email : {real_email}")
    print(f"  Login URL  : {Config.APP_URL}/login")
    print("═" * 52 + "\n")


# ─── Routes ──────────────────────────────────────────────

@monitor.route("/")
@monitor_required
def dashboard():
    logs         = ExploitLog.query.order_by(ExploitLog.timestamp.desc()).all()
    users        = User.query.all()
    participants = User.query.filter(User.role != "admin").order_by(User.created_at.desc()).all()
    return render_template("admin/monitor.html", logs=logs, users=users, participants=participants, secret=_SECRET)


@monitor.route("/create-participant", methods=["POST"])
@monitor_required
def create_participant():
    display_name = request.form.get("display_name", "").strip()
    username     = request.form.get("username", "").strip()
    real_email   = request.form.get("real_email", "").strip()

    if not display_name or not username:
        return jsonify({"status": "error", "message": "Display name and username are required."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"status": "error", "message": f"Username '{username}' is already taken."}), 400

    password       = generate_password()
    hashed_password = generate_password_hash(password)

    platform_email = generate_platform_email(username)

    user = User(
        username=username,
        password=hashed_password,
        display_name=display_name,
        platform_email=platform_email,
        email=real_email,
        role="user",
        verified=False
    )
    db.session.add(user)
    db.session.commit()

    # ── Always print to console ───────────────────────────
    log_credentials_to_console(display_name, username, password, platform_email, real_email or "N/A")

    # ── Always save to file ───────────────────────────────
    file_ok, file_err = save_credentials_to_file(display_name, username, password, platform_email, real_email or "N/A")

    # ── Attempt email if real_email provided ──────────────
    email_status = "skipped"
    email_error  = None
    if real_email:
        email_ok = send_participant_account(
            to_email=real_email,
            display_name=display_name,
            username=username,
            password=password,
            platform_email=platform_email
        )
        print(f"\nemail: {email_ok}")

    # ── Build delivery summary ────────────────────────────
    delivery = []
    delivery.append("✅ Saved to credentials_log.txt" if file_ok else f"⚠️ File save failed: {file_err}")
    delivery.append("✅ Printed to console")
    if email_status == "sent":
        delivery.append(f"✅ Email sent to {real_email}")
    elif email_status == "failed":
        delivery.append(f"⚠️ Email failed ({email_error}) — use file or console instead")
    elif email_status == "skipped":
        delivery.append("ℹ️ No real email provided — skipped email")

    return jsonify({
        "status":   "ok",
        "delivery": delivery,
        "user": {
            "id":             user.id,
            "display_name":   display_name,
            "username":       username,
            "password":       password,
            "platform_email": platform_email,
            "real_email":     real_email or "N/A",
            "login_url":      f"{Config.APP_URL}/login"
        }
    })


@monitor.route("/delete-participant/<int:user_id>", methods=["POST"])
@monitor_required
def delete_participant(user_id):
    user = db.session.get(User, user_id)
    if user and user.role != "admin":
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for("monitor.dashboard"))


@monitor.route("/send-toast", methods=["POST"])
@monitor_required
def send_toast():
    user_id = request.form.get("user_id")
    message = request.form.get("message", "")
    socketio.emit("toast_notification", {"message": message}, room=f"user_{user_id}")
    return jsonify({"status": "sent"})


@monitor.route("/clear-logs", methods=["POST"])
@monitor_required
def clear_logs():
    ExploitLog.query.delete()
    db.session.commit()
    return redirect(url_for("monitor.dashboard"))


