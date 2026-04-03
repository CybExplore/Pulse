from flask import Blueprint, render_template, request, redirect, url_for, session
from extensions import db
from models import User, Post
from helpers import current_user, login_required, log_exploit

profile = Blueprint("profile", __name__)


@profile.route("/user/<username>")
@login_required
def view_profile(username):
    me     = current_user()
    target = User.query.filter_by(username=username).first_or_404()
    posts  = Post.query.filter_by(user_id=target.id).order_by(Post.created_at.desc()).all()
    return render_template("app/profile.html", user=me, target=target, posts=posts)


# ───────────────────────────────────────────
# VULN: Vertical Privilege Escalation
#       — role parameter accepted from form
# ───────────────────────────────────────────
@profile.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    me = current_user()
    if request.method == "POST":
        me.display_name = request.form.get("display_name", me.display_name)
        me.bio          = request.form.get("bio", me.bio)
        me.email        = request.form.get("email", me.email)
        me.phone        = request.form.get("phone", me.phone)

        # ❌ VULNERABILITY: Accepts 'role' directly from user input
        new_role = request.form.get("role")
        if new_role and new_role in ["user", "moderator", "admin"]:
            if new_role != me.role:
                log_exploit(
                    vuln_type="Vertical Privilege Escalation",
                    endpoint="/settings",
                    description=f"'{me.username}' escalated role from '{me.role}' to '{new_role}' via form parameter tampering",
                    severity="critical"
                )
            me.role         = new_role
            session["role"] = new_role

        db.session.commit()
        return redirect(url_for("profile.settings"))

    return render_template("app/settings.html", user=me)
