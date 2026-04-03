"""
routes/features.py

Features + A01 Vulnerabilities:

  1.  Stories        — IDOR: view any private story by ID
  2.  Bookmarks      — IDOR: view/delete anyone's bookmarks via user_id
  3.  Post Visibility— IDOR: toggle public/private on any post by ID
  4.  Blocking       — IDOR: block/unfollow on behalf of another user; view anyone's block list
  5.  Verified badge — Missing Access Control: any user can self-verify or verify others
  6.  Comment delete — IDOR: delete any comment by ID, no ownership check
  7.  Reports        — Missing Access Control: non-moderator can view & dismiss reports
  8.  API keys       — IDOR: revoke/regenerate another user's API key by user_id
  9.  Deactivation   — IDOR: deactivate any account by user_id
  10. Pinned post    — IDOR: pin any post on any profile via user_id param
"""

import uuid
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session
from extensions import db
from models import User, Post, Comment, Story, Bookmark, Block, Report, ApiKey, Notification
from helpers import current_user, login_required, log_exploit

features = Blueprint("features", __name__)


# ═══════════════════════════════════════════
#  1. STORIES
# ═══════════════════════════════════════════

@features.route("/stories/new", methods=["POST"])
@login_required
def new_story():
    me         = current_user()
    content    = request.form.get("content", "").strip()
    is_private = request.form.get("is_private") == "on"
    if not content:
        return jsonify({"status": "error", "message": "Content required"}), 400

    story = Story(
        user_id=me.id,
        content=content,
        is_private=is_private,
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    db.session.add(story)
    db.session.commit()
    return jsonify({"status": "ok", "story_id": story.id})


# ───────────────────────────────────────────
# VULN 1: IDOR — View any private story by ID
# ───────────────────────────────────────────
@features.route("/stories/<int:story_id>")
@login_required
def view_story(story_id):
    me    = current_user()
    story = db.session.get(Story, story_id)
    if not story:
        return jsonify({"status": "error", "message": "Story not found"}), 404

    # ❌ VULNERABILITY: No ownership or privacy check
    if story.is_private and story.user_id != me.id:
        log_exploit(
            vuln_type="IDOR — Private Story Access",
            endpoint=f"/stories/{story_id}",
            description=f"@{me.username} accessed a private story (ID {story_id}) belonging to @{story.author.username}",
            severity="high"
        )

    return jsonify({
        "id":         story.id,
        "content":    story.content,
        "author":     story.author.username,
        "is_private": story.is_private,
        "expires_at": story.expires_at.isoformat(),
        "created_at": story.created_at.strftime("%H:%M")
    })


@features.route("/stories")
@login_required
def stories_feed():
    me     = current_user()
    # Active stories — includes private ones (IDOR surface)
    stories = Story.query.filter(
        Story.expires_at > datetime.utcnow()
    ).order_by(Story.created_at.desc()).all()
    return render_template("app/stories.html", user=me, stories=stories)


# ═══════════════════════════════════════════
#  2. BOOKMARKS
# ═══════════════════════════════════════════

@features.route("/bookmarks/add", methods=["POST"])
@login_required
def add_bookmark():
    me      = current_user()
    post_id = request.form.get("post_id", type=int)
    if not post_id:
        return jsonify({"status": "error"}), 400

    existing = Bookmark.query.filter_by(user_id=me.id, post_id=post_id).first()
    if not existing:
        db.session.add(Bookmark(user_id=me.id, post_id=post_id))
        db.session.commit()
    return jsonify({"status": "ok"})


@features.route("/bookmarks/remove", methods=["POST"])
@login_required
def remove_bookmark():
    me      = current_user()
    post_id = request.form.get("post_id", type=int)

    # ❌ VULNERABILITY: user_id from form — delete anyone's bookmark
    user_id = request.form.get("user_id", default=me.id, type=int)

    if user_id != me.id:
        target = db.session.get(User, user_id)
        log_exploit(
            vuln_type="IDOR — Remove Another User's Bookmark",
            endpoint="/bookmarks/remove",
            description=f"@{me.username} removed a bookmark belonging to @{target.username if target else user_id}",
            severity="medium"
        )

    record = Bookmark.query.filter_by(user_id=user_id, post_id=post_id).first()
    if record:
        db.session.delete(record)
        db.session.commit()
    return jsonify({"status": "ok"})


# ───────────────────────────────────────────
# VULN 2: IDOR — View anyone's bookmarks
# ───────────────────────────────────────────
@features.route("/bookmarks")
@login_required
def bookmarks():
    me = current_user()

    # ❌ VULNERABILITY: user_id from query param
    target_id = request.args.get("user_id", me.id, type=int)
    target    = db.session.get(User, target_id)

    if not target:
        return redirect(url_for("features.bookmarks"))

    if target.id != me.id:
        log_exploit(
            vuln_type="IDOR — View Another User's Bookmarks",
            endpoint=f"/bookmarks?user_id={target_id}",
            description=f"@{me.username} viewed the bookmarks of @{target.username} via user_id parameter",
            severity="medium"
        )

    saved = Bookmark.query.filter_by(user_id=target.id)\
                          .order_by(Bookmark.created_at.desc()).all()
    return render_template("app/bookmarks.html", user=me, target=target, bookmarks=saved)


# ═══════════════════════════════════════════
#  3. POST VISIBILITY CONTROL
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 3: IDOR — Toggle visibility on any post
# ───────────────────────────────────────────
@features.route("/post/<int:post_id>/visibility", methods=["POST"])
@login_required
def toggle_visibility(post_id):
    me   = current_user()
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({"status": "error", "message": "Post not found"}), 404

    # ❌ VULNERABILITY: No ownership check
    if post.user_id != me.id:
        log_exploit(
            vuln_type="IDOR — Post Visibility Manipulation",
            endpoint=f"/post/{post_id}/visibility",
            description=f"@{me.username} changed the visibility of @{post.author.username}'s post (ID {post_id}) from {'private' if post.is_private else 'public'} to {'public' if post.is_private else 'private'}",
            severity="high"
        )

    post.is_private = not post.is_private
    db.session.commit()
    return jsonify({"status": "ok", "is_private": post.is_private})


# ═══════════════════════════════════════════
#  4. BLOCKING
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 4a: IDOR — Block on behalf of another user
# ───────────────────────────────────────────
@features.route("/block", methods=["POST"])
@login_required
def block_user():
    me         = current_user()
    blocked_id = request.form.get("blocked_id", type=int)

    # ❌ VULNERABILITY: blocker_id from form
    blocker_id = request.form.get("blocker_id", default=me.id, type=int)

    blocker = db.session.get(User, blocker_id)
    blocked = db.session.get(User, blocked_id)

    if not blocker or not blocked:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if blocker_id != me.id:
        log_exploit(
            vuln_type="IDOR — Block on Behalf of Another User",
            endpoint="/block",
            description=f"@{me.username} forced @{blocker.username} to block @{blocked.username} via blocker_id parameter tampering",
            severity="high"
        )

    existing = Block.query.filter_by(blocker_id=blocker_id, blocked_id=blocked_id).first()
    if not existing:
        db.session.add(Block(blocker_id=blocker_id, blocked_id=blocked_id))
        db.session.commit()
    return jsonify({"status": "ok"})


@features.route("/unblock", methods=["POST"])
@login_required
def unblock_user():
    me         = current_user()
    blocked_id = request.form.get("blocked_id", type=int)
    blocker_id = request.form.get("blocker_id", default=me.id, type=int)  # VULN

    if blocker_id != me.id:
        blocker = db.session.get(User, blocker_id)
        blocked = db.session.get(User, blocked_id)
        log_exploit(
            vuln_type="IDOR — Unblock on Behalf of Another User",
            endpoint="/unblock",
            description=f"@{me.username} force-unblocked @{blocked.username if blocked else blocked_id} on behalf of @{blocker.username if blocker else blocker_id}",
            severity="medium"
        )

    record = Block.query.filter_by(blocker_id=blocker_id, blocked_id=blocked_id).first()
    if record:
        db.session.delete(record)
        db.session.commit()
    return jsonify({"status": "ok"})


# ───────────────────────────────────────────
# VULN 4b: Missing Access Control — view anyone's block list
# ───────────────────────────────────────────
@features.route("/blocks")
@login_required
def block_list():
    me        = current_user()
    target_id = request.args.get("user_id", me.id, type=int)
    target    = db.session.get(User, target_id)

    if not target:
        return redirect(url_for("features.block_list"))

    if target.id != me.id:
        log_exploit(
            vuln_type="Missing Access Control — View Another User's Block List",
            endpoint=f"/blocks?user_id={target_id}",
            description=f"@{me.username} viewed the block list of @{target.username}",
            severity="medium"
        )

    blocks = Block.query.filter_by(blocker_id=target.id).all()
    return render_template("app/blocks.html", user=me, target=target, blocks=blocks)


# ═══════════════════════════════════════════
#  5. VERIFIED BADGE
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 5: Missing Access Control — any user can
# grant verified badge to themselves or anyone
# ───────────────────────────────────────────
@features.route("/verify", methods=["POST"])
@login_required
def set_verified():
    me        = current_user()

    # ❌ VULNERABILITY: No admin check — any logged-in user can verify any account
    target_id = request.form.get("user_id", me.id, type=int)
    verified  = request.form.get("verified", "true").lower() == "true"
    target    = db.session.get(User, target_id)

    if not target:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if me.role != "admin":
        log_exploit(
            vuln_type="Missing Access Control — Verified Badge Manipulation",
            endpoint="/verify",
            description=f"@{me.username} (role: {me.role}) {'granted' if verified else 'revoked'} the verified badge {'for' if target_id != me.id else 'to themselves'} @{target.username}",
            severity="high"
        )

    target.verified = verified
    db.session.commit()
    return jsonify({"status": "ok", "verified": target.verified})


# ═══════════════════════════════════════════
#  6. COMMENT DELETION
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 6: IDOR — Delete any comment by ID
# ───────────────────────────────────────────
@features.route("/comment/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    me      = current_user()
    comment = db.session.get(Comment, comment_id)

    if not comment:
        return jsonify({"status": "error", "message": "Comment not found"}), 404

    # ❌ VULNERABILITY: No ownership check
    if comment.user_id != me.id:
        log_exploit(
            vuln_type="IDOR — Comment Deletion",
            endpoint=f"/comment/{comment_id}/delete",
            description=f"@{me.username} deleted a comment (ID {comment_id}) belonging to @{comment.author.username}",
            severity="high"
        )

    db.session.delete(comment)
    db.session.commit()
    return jsonify({"status": "ok"})


# ═══════════════════════════════════════════
#  7. REPORT SYSTEM
# ═══════════════════════════════════════════

@features.route("/report", methods=["POST"])
@login_required
def submit_report():
    me          = current_user()
    target_type = request.form.get("target_type", "").strip()
    target_id   = request.form.get("target_id", type=int)
    reason      = request.form.get("reason", "").strip()

    if not target_type or not target_id or not reason:
        return jsonify({"status": "error", "message": "All fields required"}), 400

    report = Report(
        reporter_id=me.id,
        target_type=target_type,
        target_id=target_id,
        reason=reason
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({"status": "ok", "message": "Report submitted."})


# ───────────────────────────────────────────
# VULN 7a: Missing Access Control — any user
# can view all reports (moderator-only action)
# ───────────────────────────────────────────
@features.route("/reports")
@login_required
def view_reports():
    me = current_user()

    # ❌ VULNERABILITY: No moderator/admin role check
    if me.role not in ["moderator", "admin"]:
        log_exploit(
            vuln_type="Missing Access Control — View All Reports",
            endpoint="/reports",
            description=f"@{me.username} (role: {me.role}) accessed the full reports list without moderator privileges",
            severity="high"
        )

    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template("app/reports.html", user=me, reports=reports)


# ───────────────────────────────────────────
# VULN 7b: Missing Access Control — any user
# can dismiss/action reports
# ───────────────────────────────────────────
@features.route("/reports/<int:report_id>/dismiss", methods=["POST"])
@login_required
def dismiss_report(report_id):
    me     = current_user()
    report = db.session.get(Report, report_id)

    if not report:
        return jsonify({"status": "error", "message": "Report not found"}), 404

    # ❌ VULNERABILITY: No moderator check
    if me.role not in ["moderator", "admin"]:
        log_exploit(
            vuln_type="Missing Access Control — Dismiss Report Without Moderator Role",
            endpoint=f"/reports/{report_id}/dismiss",
            description=f"@{me.username} (role: {me.role}) dismissed report ID {report_id} without moderator privileges",
            severity="high"
        )

    report.status = "dismissed"
    db.session.commit()
    return jsonify({"status": "ok"})


# ═══════════════════════════════════════════
#  8. API KEY MANAGEMENT
# ═══════════════════════════════════════════

@features.route("/api/keys")
@login_required
def list_api_keys():
    me   = current_user()
    keys = ApiKey.query.filter_by(user_id=me.id).all()
    return render_template("app/api_keys.html", user=me, keys=keys)


@features.route("/api/keys/generate", methods=["POST"])
@login_required
def generate_api_key():
    me    = current_user()
    label = request.form.get("label", "Default").strip()
    key   = ApiKey(
        user_id=me.id,
        key=uuid.uuid4().hex + uuid.uuid4().hex,
        label=label
    )
    db.session.add(key)
    db.session.commit()
    return jsonify({"status": "ok", "key": key.key, "id": key.id})


# ───────────────────────────────────────────
# VULN 8: IDOR — Revoke another user's API key
# ───────────────────────────────────────────
@features.route("/api/keys/<int:key_id>/revoke", methods=["POST"])
@login_required
def revoke_api_key(key_id):
    me  = current_user()
    key = db.session.get(ApiKey, key_id)

    if not key:
        return jsonify({"status": "error", "message": "Key not found"}), 404

    # ❌ VULNERABILITY: No ownership check
    if key.user_id != me.id:
        owner = db.session.get(User, key.user_id)
        log_exploit(
            vuln_type="IDOR — API Key Revocation",
            endpoint=f"/api/keys/{key_id}/revoke",
            description=f"@{me.username} revoked an API key (ID {key_id}) belonging to @{owner.username if owner else key.user_id}",
            severity="high"
        )

    key.is_active = False
    db.session.commit()
    return jsonify({"status": "ok"})


# ───────────────────────────────────────────
# VULN 8b: IDOR — Regenerate another user's API key
# ───────────────────────────────────────────
@features.route("/api/keys/<int:key_id>/regenerate", methods=["POST"])
@login_required
def regenerate_api_key(key_id):
    me  = current_user()
    key = db.session.get(ApiKey, key_id)

    if not key:
        return jsonify({"status": "error", "message": "Key not found"}), 404

    # ❌ VULNERABILITY: No ownership check
    if key.user_id != me.id:
        owner = db.session.get(User, key.user_id)
        log_exploit(
            vuln_type="IDOR — API Key Regeneration",
            endpoint=f"/api/keys/{key_id}/regenerate",
            description=f"@{me.username} regenerated an API key (ID {key_id}) belonging to @{owner.username if owner else key.user_id}, invalidating their access",
            severity="critical"
        )

    key.key       = uuid.uuid4().hex + uuid.uuid4().hex
    key.is_active = True
    db.session.commit()
    return jsonify({"status": "ok", "new_key": key.key})


# ═══════════════════════════════════════════
#  9. ACCOUNT DEACTIVATION
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 9: IDOR — Deactivate any account by user_id
# ───────────────────────────────────────────
@features.route("/account/deactivate", methods=["POST"])
@login_required
def deactivate_account():
    me = current_user()

    # ❌ VULNERABILITY: user_id from form — deactivate any account
    target_id = request.form.get("user_id", me.id, type=int)
    target    = db.session.get(User, target_id)

    if not target:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if target.id != me.id:
        log_exploit(
            vuln_type="IDOR — Account Deactivation",
            endpoint="/account/deactivate",
            description=f"@{me.username} deactivated the account of @{target.username} (ID: {target.id}) via user_id parameter tampering",
            severity="critical"
        )

    # Deactivation = set role to "deactivated" (soft delete)
    target.role = "deactivated"
    db.session.commit()

    # If deactivating own account, log out
    if target.id == me.id:
        session.clear()
        return jsonify({"status": "ok", "redirect": "/login"})

    return jsonify({"status": "ok", "message": f"@{target.username} has been deactivated"})


# ═══════════════════════════════════════════
#  10. PINNED POST
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 10: IDOR — Pin any post on any profile
# ───────────────────────────────────────────
@features.route("/post/<int:post_id>/pin", methods=["POST"])
@login_required
def pin_post(post_id):
    me   = current_user()
    post = db.session.get(Post, post_id)

    if not post:
        return jsonify({"status": "error", "message": "Post not found"}), 404

    # ❌ VULNERABILITY: user_id from form — pin a post on any user's profile
    profile_user_id = request.form.get("user_id", me.id, type=int)
    profile_user    = db.session.get(User, profile_user_id)

    if not profile_user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if profile_user_id != me.id:
        log_exploit(
            vuln_type="IDOR — Pin Post on Another User's Profile",
            endpoint=f"/post/{post_id}/pin",
            description=f"@{me.username} pinned post ID {post_id} on @{profile_user.username}'s profile via user_id parameter tampering",
            severity="high"
        )

    # Store pinned post ID in bio field suffix (simple approach)
    # In production this would be a separate column
    profile_user.bio = f"[pinned:{post_id}] " + (profile_user.bio or "").replace(
        profile_user.bio[:profile_user.bio.find("]")+2] if "[pinned:" in (profile_user.bio or "") else "", ""
    ).strip()
    db.session.commit()

    return jsonify({"status": "ok", "message": f"Post pinned on @{profile_user.username}'s profile"})


@features.route("/post/<int:post_id>/unpin", methods=["POST"])
@login_required
def unpin_post(post_id):
    me              = current_user()
    profile_user_id = request.form.get("user_id", me.id, type=int)  # VULN
    profile_user    = db.session.get(User, profile_user_id)

    if not profile_user:
        return jsonify({"status": "error"}), 404

    if profile_user.bio and "[pinned:" in profile_user.bio:
        import re
        profile_user.bio = re.sub(r'\[pinned:\d+\]\s*', '', profile_user.bio).strip()
        db.session.commit()

    return jsonify({"status": "ok"})