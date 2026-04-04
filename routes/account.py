"""
routes/account.py

Handles:
  - Forgot password   (VULN: predictable token, no expiry)
  - Reset password    (VULN: token never expires, brute-forceable)
  - Change password   (VULN: no current password verification)
  - Reset email       (VULN: IDOR — change any user's platform email by ID)
"""

import hashlib
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from extensions import db
from models import User, PasswordResetToken
from helpers import current_user, login_required, log_exploit, send_reset_email
from config import Config
from werkzeug.security import generate_password_hash

account = Blueprint("account", __name__)


# ─── Helpers ─────────────────────────────────────────────

def generate_reset_token(username):
    """
    ❌ VULNERABILITY: Token is derived from username alone.
    Anyone who knows the username can generate the correct token
    and reset that user's password without receiving any email.
    """
    raw = f"reset-{username}-pulse"
    return hashlib.md5(raw.encode()).hexdigest()   # VULN: MD5 + predictable input


# ─── Forgot Password ─────────────────────────────────────

@account.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        platform_email = request.form.get("email", "").strip()

        user = User.query.filter_by(platform_email=platform_email).first()
        print(f"user: {user}")

        if user:
            token = generate_reset_token(user.username)

            # Save token — VULN: old tokens never invalidated
            db.session.add(PasswordResetToken(user_id=user.id, token=token))
            db.session.commit()

            # In a real app this would be emailed.
            # Here we expose the reset link directly in the response
            # so participants can see it — the vuln is that the token
            # is predictable without ever receiving this link.
            reset_url = f"{Config.APP_URL}/reset-password/{token}"
            # ─────────────────────────────────────────────
            # A01 OBSERVATION POINT (NOT USER INPUT)
            # If attacker previously modified user.email
            # via broken access control elsewhere, this becomes exploitable
            # ─────────────────────────────────────────────

            # recipient = user.email
            # recipient = user.email
            recipient = user.email or user.platform_email   # fallback

            # Log suspicious mismatch (A01 evidence layer)
            if user.email and user.platform_email and user.email != user.platform_email:
                log_exploit(
                    vuln_type="Broken Access Control — Account Recovery Data Manipulation (A01:2025)",
                    endpoint="/forgot-password",
                    description=(
                        f"User '{user.username}' has mismatched recovery data. "
                        f"platform_email='{user.email}' vs real_email='{user.email}'. "
                        f"Password reset sent to potentially attacker-controlled destination."
                    ),
                    severity="critical"
                )

            send_reset_email(recipient, reset_url)

            message = {
                "type":  "ok",
                "text":  f"Password reset link generated.",
                # "link":  reset_url   # VULN: link shown on page (simulates email)
            }
        else:
            # VULN: confirms whether a username exists (user enumeration)
            message = {"type": "error", "text": "No account found with that username."}

    return render_template("auth/forgot_password.html", message=message)


# ─── Reset Password ──────────────────────────────────────

@account.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # ❌ VULNERABILITY: No expiry check — tokens are valid forever
    record = PasswordResetToken.query.filter_by(token=token, used=False).first()

    if not record:
        return render_template("auth/reset_password.html",
                               error="Invalid or already used reset link.", token=token)

    error = None
    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        if not new_password:
            error = "Password cannot be empty."
        else:
            user          = record.user
            user.password = generate_password_hash(new_password)   # VULN: stored in plaintext
            record.used   = True
            db.session.commit()

            log_exploit(
                vuln_type="Predictable Password Reset Token",
                endpoint=f"/reset-password/{token}",
                description=f"Password for @{user.username} was reset using a predictable MD5 token derived from their username",
                severity="critical"
            )

            return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", error=error, token=token)


# ─── Change Password (authenticated) ────────────────────

@account.route("/settings/change-password", methods=["POST"])
@login_required
def change_password():
    me           = current_user()
    new_password = request.form.get("new_password", "").strip()
    confirm      = request.form.get("confirm_password", "").strip()

    if not new_password:
        return jsonify({"status": "error", "message": "Password cannot be empty."}), 400

    if new_password != confirm:
        return jsonify({"status": "error", "message": "Passwords do not match."}), 400

    # ❌ VULNERABILITY: No current password verification
    # An attacker with a hijacked session can silently change the password
    log_exploit(
        vuln_type="Missing Current Password Verification",
        endpoint="/settings/change-password",
        description=f"@{me.username} changed their password with no verification of current password — session hijack enables silent account takeover",
        severity="high"
    )

    me.password = generate_password_hash(new_password)   # VULN: stored in plaintext
    db.session.commit()
    return jsonify({"status": "ok", "message": "Password updated successfully."})


# ─── Reset Platform Email ────────────────────────────────
@account.route("/settings/change-email", methods=["POST"])
@login_required
def change_email():
    
    me        = current_user()
    new_email = request.form.get("email", "").strip()

    # ❌ VULNERABILITY: No ownership check on target user
    # The target_user_id is taken directly from the form —
    # any logged-in user can change any other user's platform email
    target_id   = request.form.get("user_id", str(me.id))
    target_user = db.session.get(User, target_id)

    if not target_user:
        return jsonify({"status": "error", "message": "User not found."}), 404

    if not new_email:
        return jsonify({"status": "error", "message": "Email cannot be empty."}), 400

    if str(target_user.id) != str(me.id):
        log_exploit(
            vuln_type="IDOR — Platform Email Takeover",
            endpoint="/settings/change-email",
            description=f"@{me.username} changed the platform email of @{target_user.username} (ID: {target_user.id}) via user_id parameter tampering",
            severity="critical"
        )

    target_user.email = new_email
    db.session.commit()
    return jsonify({"status": "ok", "message": "Email updated successfully."})