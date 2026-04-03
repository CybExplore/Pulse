from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session
from extensions import db
from models import User, Post, ExploitLog
from helpers import current_user, login_required, log_exploit

admin = Blueprint("admin", __name__)


# ───────────────────────────────────────────
# VULN: Forced Browsing + Missing Access Control
#       No auth required — anyone can reach /admin
# ───────────────────────────────────────────
@admin.route("/admin")
def admin_panel():
    me = current_user()

    if me and me.role != "admin":
        log_exploit(
            vuln_type="Missing Function-Level Access Control",
            endpoint="/admin",
            description=f"'{me.username}' (role: {me.role}) accessed the admin panel without admin privileges",
            severity="critical"
        )
    elif not me:
        log_exploit(
            vuln_type="Forced Browsing — Unauthenticated Admin Access",
            endpoint="/admin",
            description="An unauthenticated visitor accessed /admin directly",
            severity="critical"
        )

    users = User.query.all()
    posts = Post.query.order_by(Post.created_at.desc()).all()
    logs  = ExploitLog.query.order_by(ExploitLog.timestamp.desc()).limit(50).all()
    return render_template("admin/panel.html", users=users, posts=posts, logs=logs, user=me)


# ───────────────────────────────────────────
# VULN: Forced Browsing — exposes all credentials
# ───────────────────────────────────────────
@admin.route("/debug/users")
def debug_users():
    me = current_user()
    if me and me.role != "admin":
        log_exploit(
            vuln_type="Forced Browsing — Debug Endpoint",
            endpoint="/debug/users",
            description=f"'{me.username}' accessed /debug/users, exposing all credentials and PII",
            severity="critical"
        )
    elif not me:
        log_exploit(
            vuln_type="Forced Browsing — Unauthenticated Debug Access",
            endpoint="/debug/users",
            description="An unauthenticated visitor accessed /debug/users",
            severity="critical"
        )

    # VULN: plaintext passwords exposed
    return jsonify([{
        "id":       u.id,
        "username": u.username,
        "password": u.password,
        "email":    u.email,
        "phone":    u.phone,
        "role":     u.role
    } for u in User.query.all()])


# ───────────────────────────────────────────
# VULN: Missing Access Control — any user can change roles
# ───────────────────────────────────────────
@admin.route("/admin/set-role", methods=["POST"])
@login_required
def set_role():
    me      = current_user()
    user_id = request.form.get("user_id")
    role    = request.form.get("role")

    if me.role != "admin":
        log_exploit(
            vuln_type="Missing Function-Level Access Control — Role Assignment",
            endpoint="/admin/set-role",
            description=f"'{me.username}' (role: {me.role}) set user {user_id}'s role to '{role}'",
            severity="critical"
        )

    target = db.session.get(User, user_id)
    if target and role in ["user", "moderator", "admin"]:
        target.role = role
        db.session.commit()

    return redirect(url_for("admin.admin_panel"))


# ───────────────────────────────────────────
# VULN: Missing Access Control — any user can delete accounts
# ───────────────────────────────────────────
@admin.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    me     = current_user()
    target = db.session.get(User, user_id)
    if not target:
        return redirect(url_for("admin.admin_panel"))

    if me.role != "admin":
        log_exploit(
            vuln_type="Missing Function-Level Access Control — Account Deletion",
            endpoint=f"/admin/delete-user/{user_id}",
            description=f"'{me.username}' (role: {me.role}) deleted account of @{target.username}",
            severity="critical"
        )

    db.session.delete(target)
    db.session.commit()
    return redirect(url_for("admin.admin_panel"))
