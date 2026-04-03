"""
routes/social.py

Handles follow, unfollow, followers/following lists, notifications.

A01 Vulnerabilities:
  1. IDOR — Follow as another user (follower_id from form, not session)
  2. IDOR — Unfollow on behalf of another user
  3. Missing Access Control — view anyone's followers/following list
  4. IDOR — Mark another user's notifications as read
"""

from flask import Blueprint, request, jsonify, render_template, session
from extensions import db, socketio
from models import User, Follow, Notification
from helpers import current_user, login_required, log_exploit

social = Blueprint("social", __name__)


def push_notification(user_id, actor_id, notif_type, message):
    """Save notification to DB and push via Socket.IO."""
    notif = Notification(
        user_id=user_id,
        actor_id=actor_id,
        type=notif_type,
        message=message
    )
    db.session.add(notif)
    db.session.commit()

    socketio.emit("new_notification", {
        "id":      notif.id,
        "type":    notif_type,
        "message": message,
        "time":    notif.created_at.strftime("%H:%M")
    }, room=f"user_{user_id}")

    return notif


# ── Follow ────────────────────────────────────────────────
@social.route("/follow", methods=["POST"])
@login_required
def follow():
    me           = current_user()
    following_id = request.form.get("following_id", type=int)

    # ❌ VULNERABILITY: follower_id is taken from the form — not from session
    # A student can set follower_id to any user ID to make anyone follow anyone
    follower_id  = request.form.get("follower_id", default=me.id, type=int)

    if not following_id:
        return jsonify({"status": "error", "message": "Missing following_id"}), 400

    if follower_id == following_id:
        return jsonify({"status": "error", "message": "Cannot follow yourself"}), 400

    follower  = db.session.get(User, follower_id)
    following = db.session.get(User, following_id)

    if not follower or not following:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Log if acting as someone else
    if follower_id != me.id:
        log_exploit(
            vuln_type="IDOR — Follow as Another User",
            endpoint="/follow",
            description=f"@{me.username} forced @{follower.username} to follow @{following.username} via follower_id parameter tampering",
            severity="high"
        )

    # Check not already following
    exists = Follow.query.filter_by(follower_id=follower_id, following_id=following_id).first()
    if exists:
        return jsonify({"status": "error", "message": "Already following"}), 400

    db.session.add(Follow(follower_id=follower_id, following_id=following_id))

    # Update counts
    follower.following_count  = (follower.following_count  or 0) + 1
    following.follower_count  = (following.follower_count  or 0) + 1
    db.session.commit()

    # Notify the person being followed
    push_notification(
        user_id=following_id,
        actor_id=follower_id,
        notif_type="follow",
        message=f"@{follower.username} started following you"
    )

    return jsonify({
        "status":          "ok",
        "follower_count":  following.follower_count,
        "following_count": follower.following_count
    })


# ── Unfollow ──────────────────────────────────────────────
@social.route("/unfollow", methods=["POST"])
@login_required
def unfollow():
    me           = current_user()
    following_id = request.form.get("following_id", type=int)

    # ❌ VULNERABILITY: follower_id from form — can unfollow on behalf of anyone
    follower_id  = request.form.get("follower_id", default=me.id, type=int)

    if not following_id:
        return jsonify({"status": "error", "message": "Missing following_id"}), 400

    follower  = db.session.get(User, follower_id)
    following = db.session.get(User, following_id)

    if not follower or not following:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if follower_id != me.id:
        log_exploit(
            vuln_type="IDOR — Unfollow on Behalf of Another User",
            endpoint="/unfollow",
            description=f"@{me.username} force-unfollowed @{following.username} on behalf of @{follower.username} via follower_id parameter tampering",
            severity="high"
        )

    record = Follow.query.filter_by(follower_id=follower_id, following_id=following_id).first()
    if not record:
        return jsonify({"status": "error", "message": "Not following"}), 400

    db.session.delete(record)

    follower.following_count  = max((follower.following_count  or 1) - 1, 0)
    following.follower_count  = max((following.follower_count  or 1) - 1, 0)
    db.session.commit()

    return jsonify({
        "status":          "ok",
        "follower_count":  following.follower_count,
        "following_count": follower.following_count
    })


# ── Check follow status ───────────────────────────────────
@social.route("/follow/status/<int:target_id>")
@login_required
def follow_status(target_id):
    me     = current_user()
    exists = Follow.query.filter_by(follower_id=me.id, following_id=target_id).first()
    return jsonify({"following": bool(exists)})


# ───────────────────────────────────────────────────────────
# VULN: Missing Access Control — anyone can view any user's
#       followers and following list
# ───────────────────────────────────────────────────────────
@social.route("/user/<username>/followers")
@login_required
def followers(username):
    me     = current_user()
    target = User.query.filter_by(username=username).first_or_404()

    # ❌ VULNERABILITY: No privacy check — private accounts exposed
    if target.id != me.id:
        log_exploit(
            vuln_type="Missing Access Control — Followers List",
            endpoint=f"/user/{username}/followers",
            description=f"@{me.username} accessed the full followers list of @{target.username}",
            severity="medium"
        )

    followers = [f.follower for f in Follow.query.filter_by(following_id=target.id).all()]
    return render_template("app/follow_list.html", user=me, target=target,
                           list_type="Followers", people=followers)


@social.route("/user/<username>/following")
@login_required
def following(username):
    me     = current_user()
    target = User.query.filter_by(username=username).first_or_404()

    # ❌ VULNERABILITY: No privacy check
    if target.id != me.id:
        log_exploit(
            vuln_type="Missing Access Control — Following List",
            endpoint=f"/user/{username}/following",
            description=f"@{me.username} accessed the full following list of @{target.username}",
            severity="medium"
        )

    following = [f.following for f in Follow.query.filter_by(follower_id=target.id).all()]
    return render_template("app/follow_list.html", user=me, target=target,
                           list_type="Following", people=following)


# ── Notifications ─────────────────────────────────────────
@social.route("/notifications")
@login_required
def notifications():
    me    = current_user()
    notifs = Notification.query.filter_by(user_id=me.id)\
                               .order_by(Notification.created_at.desc()).limit(50).all()
    # Mark all as read
    Notification.query.filter_by(user_id=me.id, is_read=False).update({"is_read": True})
    db.session.commit()
    return render_template("app/notifications.html", user=me, notifications=notifs)


@social.route("/notifications/unread-count")
@login_required
def unread_count():
    me    = current_user()
    count = Notification.query.filter_by(user_id=me.id, is_read=False).count()
    unread_msgs = __import__("models").Message.query.filter_by(
        receiver_id=me.id, is_read=False
    ).count()
    return jsonify({"notifications": count, "messages": unread_msgs})


# ───────────────────────────────────────────────────────────
# VULN: IDOR — Mark another user's notifications as read
# ───────────────────────────────────────────────────────────
@social.route("/notifications/mark-read", methods=["POST"])
@login_required
def mark_read():
    me      = current_user()
    # ❌ VULNERABILITY: user_id from form — can clear anyone's notifications
    user_id = request.form.get("user_id", default=me.id, type=int)

    if user_id != me.id:
        target = db.session.get(User, user_id)
        log_exploit(
            vuln_type="IDOR — Clear Another User's Notifications",
            endpoint="/notifications/mark-read",
            description=f"@{me.username} marked all notifications of @{target.username if target else user_id} as read via user_id parameter tampering",
            severity="medium"
        )

    Notification.query.filter_by(user_id=user_id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"status": "ok"})