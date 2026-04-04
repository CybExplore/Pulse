from functools import wraps
from flask import session, request, redirect, url_for
from extensions import db, socketio
from models import User, ExploitLog

from flask_mail import Mail, Message
from flask import Flask

from config import Config


app = Flask(__name__)

mail = Mail(app)

def log_exploit(vuln_type, endpoint, description, severity="high"):
    """Log an exploit and push real-time alert to the monitor dashboard."""
    user_id  = session.get("user_id")
    username = session.get("username", "anonymous")
    ip       = request.remote_addr

    log = ExploitLog(
        attacker_id=user_id,
        attacker_username=username,
        attacker_ip=ip,
        vuln_type=vuln_type,
        endpoint=endpoint,
        description=description,
        severity=severity
    )
    db.session.add(log)
    db.session.commit()

    socketio.emit("new_exploit", {
        "id":          log.id,
        "attacker":    username,
        "attacker_id": user_id,
        "ip":          ip,
        "vuln_type":   vuln_type,
        "endpoint":    endpoint,
        "description": description,
        "severity":    severity,
        "timestamp":   log.timestamp.strftime("%H:%M:%S")
    }, room="admin_room")

    return log


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        # Also verify the user still exists in DB
        # handles cases where DB was reset but session cookie is still active
        user = db.session.get(User, session.get("user_id"))
        if not user:
            session.clear()
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def send_account_email(to_email, username, password):
    msg = Message(
        subject="Pulse Monitor Account Created",
        recipients=[to_email]
    )

    msg.body = f"""
Hello,

Your monitor account has been created.

Username: {username}
Password: {password}

Login URL: {Config.APP_URL}

⚠️ Keep this secure.
"""

    mail.send(msg)

from flask_mail import Message
from extensions import mail
from config import Config


def send_reset_email(recipient_email, reset_url):
    """
    Sends password reset email to user.
    """

    subject = "Pulse Password Reset Request"

    body = f"""
Hello,

We received a request to reset your password.

Click the link below to reset it:

{reset_url}

If you did not request this, ignore this email.

Regards,
Pulse Security Team
"""

    msg = Message(
        subject=subject,
        recipients=[recipient_email],
        body=body,
        sender=Config.MAIL_DEFAULT_SENDER
    )

    try:
        mail.send(msg)
        print(f"[MAIL] Reset email sent to {recipient_email}")
        return True

    except Exception as e:
        print(f"[MAIL ERROR] Failed to send reset email: {e}")
        return False



def send_participant_account(display_name, platform_email, to_email, username, password):
    
    msg = Message(
        subject="Pulse Account Created",
        recipients=[to_email]
    )

    msg.body = f"""
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;background:#0a0a0f;color:#e8e8f0;border-radius:12px;">
          <div style="font-size:28px;font-weight:700;color:#a78bfa;margin-bottom:3px;">Pulse</div>
          <!--<div style="font-size:14px;color:#7070a0;margin-bottom:28px;"></div>-->
          <p style="font-size:15px;margin-bottom:20px;">
            Hi <b>{display_name}</b>, your CybExplore A01:2025 account is ready. You can now access your account and start interacting with it, but please do not perform any attacks until the event begins. For now, you can make posts, follow others, send messages, and explore the platform.
          </p>
          <div style="background:#1a1a24;border:1px solid #2a2a38;border-radius:10px;padding:20px;margin-bottom:24px;">
            <div style="margin-bottom:14px;">
              <div style="font-size:11px;color:#7070a0;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Login URL</div>
              <div style="font-size:14px;font-family:monospace;color:#a78bfa;">
                <a href="{Config.APP_URL}/login">Login</a>
              </div>
            </div>
            <div style="margin-bottom:14px;">
              <div style="font-size:11px;color:#7070a0;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Username</div>
              <div style="font-size:14px;font-family:monospace;color:#e8e8f0;">{username}</div>
            </div>
            <div style="margin-bottom:14px;">
              <div style="font-size:11px;color:#7070a0;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Password</div>
              <div style="font-size:14px;font-family:monospace;color:#e8e8f0;">{password}</div>
            </div>
            <div>
              <div style="font-size:11px;color:#7070a0;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;">Platform Email</div>
              <div style="font-size:14px;font-family:monospace;color:#e8e8f0;">{platform_email}</div>
            </div>
          </div>
          <p style="font-size:12px;color:#7070a0;line-height:1.6;">
            Training purposes only. Do not share your credentials.
          </p>
        </div>
"""

    mail.send(msg)

