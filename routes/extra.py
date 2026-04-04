"""
routes/extra.py

Features:
  - Profile picture upload
  - Search
  - Export user data

A01 Vulnerabilities:
  1. IDOR — Upload profile picture for another user (user_id from form)
  2. Path Traversal — Serve any file via /uploads/<filename> (no path sanitization)
  3. Missing Access Control — Search exposes private posts and non-public users
  4. Missing Access Control — View any user's search history by user_id
  5. IDOR — Export any user's data by user_id
  6. Missing Access Control — Download any export file by filename
"""

import os
import json
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, send_from_directory, send_file
from extensions import db
from models import User, Post, Message, Follow, UserExport, SearchLog
from helpers import current_user, login_required, log_exploit
from config import Config

extra = Blueprint("extra", __name__)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "static", "uploads")
EXPORT_FOLDER = os.path.join(os.path.dirname(__file__), "..", "static", "exports")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(EXPORT_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


# ═══════════════════════════════════════════
#  PROFILE PICTURE UPLOAD
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 1: IDOR — Upload avatar for any user
# ───────────────────────────────────────────
@extra.route("/settings/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    me   = current_user()
    file = request.files.get("avatar")

    # ❌ VULNERABILITY: user_id taken from form — attacker can
    # upload a profile picture on behalf of any user
    target_id = request.form.get("user_id", str(me.id))
    target    = db.session.get(User, target_id)

    if not target:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if str(target.id) != str(me.id):
        log_exploit(
            vuln_type="IDOR — Profile Picture Takeover",
            endpoint="/settings/upload-avatar",
            description=f"@{me.username} uploaded a profile picture on behalf of @{target.username} (ID: {target.id}) via user_id parameter tampering",
            severity="high"
        )

    if not file or file.filename == "":
        return jsonify({"status": "error", "message": "No file selected"}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""

    # ❌ VULNERABILITY: No file type validation beyond extension check
    # A student can rename a PHP/HTML file to .jpg and upload it
    # ALSO: filename not sanitized — path traversal possible
    filename  = f"avatar_{target_id}_{uuid.uuid4().hex[:8]}.{ext}"
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)

    # Store filename on user record (reuse phone field for simplicity, or add column)
    target.phone = filename  # just tracking it — in real app would be separate column
    db.session.commit()

    return jsonify({
        "status":   "ok",
        "filename": filename,
        "url":      f"/uploads/{filename}"
    })


# ───────────────────────────────────────────
# VULN 2: Missing Access Control — serve any uploaded file
# No authentication required, no path check
# ───────────────────────────────────────────
@extra.route("/uploads/<path:filename>")
def serve_upload(filename):
    # ❌ VULNERABILITY: No login required, no ownership check
    # Any file in the uploads folder is publicly accessible
    # path:filename also allows directory traversal like ../../config.py
    me = current_user()
    if me:
        # Check if this file belongs to the requesting user
        expected_prefix = f"avatar_{me.id}_"
        if not filename.startswith(expected_prefix):
            log_exploit(
                vuln_type="Missing Access Control — Unauthorized File Access",
                endpoint=f"/uploads/{filename}",
                description=f"@{me.username} accessed upload file '{filename}' which does not belong to them",
                severity="medium"
            )
    return send_from_directory(UPLOAD_FOLDER, filename)


# ═══════════════════════════════════════════
#  SEARCH
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 3: Missing Access Control — search
# exposes private posts and non-public users
# ───────────────────────────────────────────
@extra.route("/search")
@login_required
def search():
    me    = current_user()
    query = request.args.get("q", "").strip()
    results_users = []
    results_posts = []

    if query:
        # Log the search
        db.session.add(SearchLog(user_id=me.id, query=query))
        db.session.commit()

        # ❌ VULNERABILITY: Returns ALL users including admins,
        # and ALL posts including private ones
        results_users = User.query.filter(
            User.username.ilike(f"%{query}%") |
            User.display_name.ilike(f"%{query}%")
        ).all()

        results_posts = Post.query.filter(
            Post.content.ilike(f"%{query}%")
        ).order_by(Post.created_at.desc()).all()

        # Log if private posts are in results
        private_hits = [p for p in results_posts if p.is_private]
        if private_hits:
            log_exploit(
                vuln_type="Missing Access Control — Private Post Exposure via Search",
                endpoint=f"/search?q={query}",
                description=f"@{me.username} search for '{query}' returned {len(private_hits)} private post(s) belonging to other users",
                severity="high"
            )

    return render_template("app/search.html", user=me, query=query,
                           results_users=results_users, results_posts=results_posts)


# ───────────────────────────────────────────
# VULN 4: IDOR — View any user's search history
# ───────────────────────────────────────────
@extra.route("/search/history")
@login_required
def search_history():
    me = current_user()

    # ❌ VULNERABILITY: user_id from query param — view anyone's search history
    target_id = request.args.get("user_id", me.id, type=int)
    target    = db.session.get(User, target_id)

    if not target:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if target.id != me.id:
        log_exploit(
            vuln_type="IDOR — Search History Access",
            endpoint=f"/search/history?user_id={target_id}",
            description=f"@{me.username} accessed the search history of @{target.username} via user_id parameter",
            severity="medium"
        )

    logs = db.session.query(SearchLog) \
    .filter(SearchLog.user_id == target_id) \
    .order_by(SearchLog.created_at.desc()) \
    .limit(50) \
    .all()

    return render_template("app/search_history.html", user=me, target=target, logs=logs)


# ═══════════════════════════════════════════
#  DATA EXPORT
# ═══════════════════════════════════════════

# ───────────────────────────────────────────
# VULN 5: IDOR — Export any user's data
# ───────────────────────────────────────────
@extra.route("/settings/export", methods=["POST"])
@login_required
def export_data():
    me = current_user()

    # ❌ VULNERABILITY: user_id from form — export any user's data
    target_id = request.form.get("user_id", str(me.id))
    target    = db.session.get(User, target_id)

    if not target:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if str(target.id) != str(me.id):
        log_exploit(
            vuln_type="IDOR — Unauthorized Data Export",
            endpoint="/settings/export",
            description=f"@{me.username} exported the personal data of @{target.username} (ID: {target.id}) via user_id parameter tampering",
            severity="critical"
        )

    # Build export payload
    posts = Post.query.filter_by(user_id=target.id).all()
    sent  = Message.query.filter_by(sender_id=target.id).all()
    rcvd  = Message.query.filter_by(receiver_id=target.id).all()

    payload = {
        "exported_at": datetime.utcnow().isoformat(),
        "exported_by": me.username,
        "profile": {
            "id":           target.id,
            "username":     target.username,
            "display_name": target.display_name,
            "email":        target.email,
            "phone":        target.phone,
            "bio":          target.bio,
            "role":         target.role,
            "password":     target.password,   # VULN: plaintext password in export
            "created_at":   target.created_at.isoformat(),
        },
        "posts": [{"id": p.id, "content": p.content, "private": p.is_private,
                   "likes": p.likes, "created_at": p.created_at.isoformat()} for p in posts],
        "sent_messages": [{"id": m.id, "to": m.receiver_id, "content": m.content,
                           "created_at": m.created_at.isoformat()} for m in sent],
        "received_messages": [{"id": m.id, "from": m.sender_id, "content": m.content,
                               "created_at": m.created_at.isoformat()} for m in rcvd],
    }

    filename  = f"export_{target.id}_{uuid.uuid4().hex[:8]}.json"
    filepath  = os.path.join(EXPORT_FOLDER, filename)

    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)

    db.session.add(UserExport(user_id=target.id, filename=filename))
    db.session.commit()

    return jsonify({
        "status":   "ok",
        "message":  f"Export ready for @{target.username}",
        "filename": filename,
        "download": f"/settings/export/download/{filename}"
    })


# ───────────────────────────────────────────
# VULN 6: Missing Access Control — download any export file
# ───────────────────────────────────────────
@extra.route("/settings/export/download/<filename>")
@login_required
def download_export(filename):
    me = current_user()

    # ❌ VULNERABILITY: No check that this export belongs to the logged-in user
    # Any logged-in user can download any export file if they know the filename
    export = UserExport.query.filter_by(filename=filename).first()

    if export and export.user_id != me.id:
        target = db.session.get(User, export.user_id)
        log_exploit(
            vuln_type="Missing Access Control — Export File Download",
            endpoint=f"/settings/export/download/{filename}",
            description=f"@{me.username} downloaded the data export of @{target.username if target else export.user_id}",
            severity="critical"
        )

    filepath = os.path.join(EXPORT_FOLDER, filename)
    if not os.path.exists(filepath):
        return jsonify({"status": "error", "message": "Export not found"}), 404

    return send_file(filepath, as_attachment=True, download_name=filename)