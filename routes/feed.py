from flask import Blueprint, render_template, request, redirect, url_for, jsonify
from extensions import db
from models import User, Post, Comment
from helpers import current_user, login_required, log_exploit

feed = Blueprint("feed", __name__)


@feed.route("/feed")
@login_required
def home():
    me    = current_user()
    posts = Post.query.order_by(Post.created_at.desc()).limit(50).all()
    users = User.query.filter(User.id != me.id, User.role != "admin").limit(6).all()
    return render_template("app/feed.html", user=me, posts=posts, suggested=users)


@feed.route("/post/new", methods=["POST"])
@login_required
def new_post():
    me      = current_user()
    content = request.form.get("content", "").strip()
    private = request.form.get("is_private") == "on"
    if content:
        db.session.add(Post(user_id=me.id, content=content, is_private=private))
        db.session.commit()
    return redirect(url_for("feed.home"))


# ───────────────────────────────────────────
# VULN: IDOR — Edit any post by ID
# ───────────────────────────────────────────
@feed.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    me   = current_user()
    post = db.session.get(Post, post_id)
    if not post:
        return redirect(url_for("feed.home"))

    # ❌ VULNERABILITY: No ownership check
    if post.user_id != me.id:
        log_exploit(
            vuln_type="IDOR — Post Modification",
            endpoint=f"/post/{post_id}/edit",
            description=f"'{me.username}' edited a post belonging to @{post.author.username}",
            severity="high"
        )

    if request.method == "POST":
        post.content = request.form.get("content", post.content)
        db.session.commit()
        return redirect(url_for("feed.home"))

    return render_template("app/edit_post.html", user=me, post=post)


# ───────────────────────────────────────────
# VULN: IDOR — Delete any post by ID
# ───────────────────────────────────────────
@feed.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    me   = current_user()
    post = db.session.get(Post, post_id)
    if not post:
        return redirect(url_for("feed.home"))

    # ❌ VULNERABILITY: No ownership check
    if post.user_id != me.id:
        log_exploit(
            vuln_type="IDOR — Post Deletion",
            endpoint=f"/post/{post_id}/delete",
            description=f"'{me.username}' deleted a post belonging to @{post.author.username} (ID {post_id})",
            severity="high"
        )

    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("feed.home"))


# ── Like post ────────────────────────────────────────────
@feed.route("/post/<int:post_id>/like", methods=["POST"])
@login_required
def like_post(post_id):
    post = db.session.get(Post, post_id)
    if post:
        post.likes += 1
        db.session.commit()
        return jsonify({"likes": post.likes}), 200
    return jsonify({"error": "Post not found"}), 404


# ── Repost (silent) ──────────────────────────────────────
@feed.route("/post/<int:post_id>/repost", methods=["POST"])
@login_required
def repost(post_id):
    me   = current_user()
    post = db.session.get(Post, post_id)
    if not post:
        return jsonify({"error": "Post not found"}), 404

    repost = Post(
        user_id=me.id,
        content=post.content,
        is_repost=True,
        repost_of_id=post.id,
        repost_thought=None
    )
    db.session.add(repost)
    db.session.commit()
    return jsonify({"status": "ok", "message": "Reposted"}), 200


# ── Repost with thought ──────────────────────────────────
@feed.route("/post/<int:post_id>/repost-thought", methods=["POST"])
@login_required
def repost_with_thought(post_id):
    me      = current_user()
    post    = db.session.get(Post, post_id)
    thought = request.form.get("thought", "").strip()
    if not post:
        return jsonify({"error": "Post not found"}), 404
    if not thought:
        return jsonify({"error": "Thought is required"}), 400

    repost = Post(
        user_id=me.id,
        content=post.content,
        is_repost=True,
        repost_of_id=post.id,
        repost_thought=thought
    )
    db.session.add(repost)
    db.session.commit()
    return jsonify({"status": "ok", "message": "Reposted with thought"}), 200


# ── Comment on a post ────────────────────────────────────
@feed.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    me        = current_user()
    post      = db.session.get(Post, post_id)
    content   = request.form.get("content", "").strip()
    parent_id = request.form.get("parent_id", None)

    if not post or not content:
        return jsonify({"error": "Invalid request"}), 400

    comment = Comment(
        post_id=post_id,
        user_id=me.id,
        content=content,
        parent_id=int(parent_id) if parent_id else None
    )
    db.session.add(comment)
    db.session.commit()

    return jsonify({
        "status":       "ok",
        "comment_id":   comment.id,
        "username":     me.username,
        "display_name": me.display_name,
        "content":      comment.content,
        "parent_id":    comment.parent_id,
        "created_at":   comment.created_at.strftime("%b %d, %H:%M")
    }), 200


# ── Like a comment ───────────────────────────────────────
@feed.route("/comment/<int:comment_id>/like", methods=["POST"])
@login_required
def like_comment(comment_id):
    comment = db.session.get(Comment, comment_id)
    if comment:
        comment.likes += 1
        db.session.commit()
        return jsonify({"likes": comment.likes}), 200
    return jsonify({"error": "Comment not found"}), 404


# ── Load comments for a post (JSON) ─────────────────────
@feed.route("/post/<int:post_id>/comments")
@login_required
def get_comments(post_id):
    def serialize(comment):
        return {
            "id":           comment.id,
            "user_id":      comment.user_id,
            "username":     comment.author.username,
            "display_name": comment.author.display_name,
            "content":      comment.content,
            "likes":        comment.likes,
            "parent_id":    comment.parent_id,
            "created_at":   comment.created_at.strftime("%b %d, %H:%M"),
            "replies":      [serialize(r) for r in comment.replies.order_by(Comment.created_at.asc()).all()]
        }

    top_level = Comment.query.filter_by(post_id=post_id, parent_id=None)\
                             .order_by(Comment.created_at.asc()).all()
    return jsonify([serialize(c) for c in top_level]), 200
