from datetime import datetime
from extensions import db


class User(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80), unique=True, nullable=False)
    password        = db.Column(db.String(120), nullable=False)  # VULN: plaintext
    display_name    = db.Column(db.String(100))
    bio             = db.Column(db.String(300), default="")

    platform_email  = db.Column(db.String(120), default="")
    email           = db.Column(db.String(120), default="")
    
    phone           = db.Column(db.String(30),  default="")
    role            = db.Column(db.String(20),  default="user")  # user | moderator | admin
    verified        = db.Column(db.Boolean,     default=False)
    follower_count  = db.Column(db.Integer,     default=0)
    following_count = db.Column(db.Integer,     default=0)
    created_at      = db.Column(db.DateTime,    default=datetime.utcnow)


class Post(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content         = db.Column(db.String(280), nullable=False)
    likes           = db.Column(db.Integer, default=0)
    is_private      = db.Column(db.Boolean, default=False)
    # Repost fields
    is_repost       = db.Column(db.Boolean, default=False)
    repost_of_id    = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)
    repost_thought  = db.Column(db.String(280), nullable=True)  # "repost with thought"
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    author          = db.relationship("User", backref="posts")
    original_post   = db.relationship("Post", remote_side="Post.id", backref="reposts", foreign_keys=[repost_of_id])
    comments        = db.relationship("Comment", backref="post", lazy="dynamic", foreign_keys="Comment.post_id", cascade="all, delete-orphan")


class Comment(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    post_id    = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    parent_id  = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=True)  # None = top-level
    content    = db.Column(db.String(500), nullable=False)
    likes      = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    author   = db.relationship("User", backref="comments")
    replies  = db.relationship("Comment", backref=db.backref("parent", remote_side="Comment.id"),
                               lazy="dynamic", foreign_keys=[parent_id], cascade="all, delete-orphan")


class Message(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    sender_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content      = db.Column(db.String(1000), nullable=False)
    reply_to_id  = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)  # reply thread
    is_read      = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    sender       = db.relationship("User",    foreign_keys=[sender_id])
    receiver     = db.relationship("User",    foreign_keys=[receiver_id])
    reply_to     = db.relationship("Message", foreign_keys=[reply_to_id], remote_side="Message.id")


class ExploitLog(db.Model):
    id                = db.Column(db.Integer, primary_key=True)
    attacker_id       = db.Column(db.Integer)
    attacker_username = db.Column(db.String(80))
    attacker_ip       = db.Column(db.String(50))
    vuln_type         = db.Column(db.String(100))
    endpoint          = db.Column(db.String(200))
    description       = db.Column(db.String(500))
    severity          = db.Column(db.String(20))
    timestamp         = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordResetToken(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token      = db.Column(db.String(100), nullable=False)   # VULN: predictable token
    used       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # VULN: never expires
    user       = db.relationship("User", backref="reset_tokens")


class Follow(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    follower_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    follower  = db.relationship("User", foreign_keys=[follower_id],  backref="following_list")
    following = db.relationship("User", foreign_keys=[following_id], backref="followers_list")

    __table_args__ = (db.UniqueConstraint("follower_id", "following_id", name="unique_follow"),)


class Notification(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)  # recipient
    actor_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)  # who triggered
    type       = db.Column(db.String(30), nullable=False)  # follow | message | like | comment
    message    = db.Column(db.String(200))
    is_read    = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    recipient = db.relationship("User", foreign_keys=[user_id],  backref="notifications")
    actor     = db.relationship("User", foreign_keys=[actor_id])


class ProfilePicture(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    filename   = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user       = db.relationship("User", backref=db.backref("profile_picture", uselist=False))


class UserExport(db.Model):
    """Tracks data export requests — IDOR target."""
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    filename   = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user       = db.relationship("User", backref="exports")


class SearchLog(db.Model):
    """Logs all searches — missing access control exposes private data."""
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    query      = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Story(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content    = db.Column(db.String(300), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author     = db.relationship("User", backref="stories")


class Bookmark(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id    = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user       = db.relationship("User", backref="bookmarks")
    post       = db.relationship("Post", backref="bookmarked_by")
    __table_args__ = (db.UniqueConstraint("user_id", "post_id", name="unique_bookmark"),)


class Block(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    blocker_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    blocked_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    blocker     = db.relationship("User", foreign_keys=[blocker_id], backref="blocking_list")
    blocked     = db.relationship("User", foreign_keys=[blocked_id], backref="blocked_by_list")
    __table_args__ = (db.UniqueConstraint("blocker_id", "blocked_id", name="unique_block"),)


class Report(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)   # post | comment | user
    target_id   = db.Column(db.Integer, nullable=False)
    reason      = db.Column(db.String(200), nullable=False)
    status      = db.Column(db.String(20), default="pending")  # pending | dismissed | actioned
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    reporter    = db.relationship("User", backref="reports_made")


class ApiKey(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    key        = db.Column(db.String(64), unique=True, nullable=False)
    label      = db.Column(db.String(100), default="Default")
    is_active  = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user       = db.relationship("User", backref="api_keys")
