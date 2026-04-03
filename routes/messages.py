"""
routes/messages.py

A01 Vulnerabilities:
  1. IDOR — Read any DM by message ID (/messages/view/<id>)
  2. IDOR — Delete any DM by message ID (/messages/delete/<id>)
  3. IDOR — Edit any DM content by ID (/messages/edit/<id>)
  4. IDOR — Send a message as another user (sender_id from body)
"""

from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session
from extensions import db, socketio
from models import User, Message, Notification
from helpers import current_user, login_required, log_exploit

messages = Blueprint("messages", __name__)


# ── Helpers ───────────────────────────────────────────────

def push_message_notification(sender, receiver_id, msg_id):
    notif = Notification(
        user_id=receiver_id,
        actor_id=sender.id,
        type="message",
        message=f"@{sender.username} sent you a message"
    )
    db.session.add(notif)
    db.session.commit()

    socketio.emit("new_notification", {
        "type":    "message",
        "message": notif.message,
        "time":    notif.created_at.strftime("%H:%M")
    }, room=f"user_{receiver_id}")

    unread = Message.query.filter_by(receiver_id=receiver_id, is_read=False).count()
    socketio.emit("unread_messages", {"count": unread}, room=f"user_{receiver_id}")


def serialize_msg(msg):
    return {
        "id":           msg.id,
        "sender_id":    msg.sender_id,
        "receiver_id":  msg.receiver_id,
        "content":      msg.content,
        "is_read":      msg.is_read,
        "reply_to_id":  msg.reply_to_id,
        "reply_preview": msg.reply_to.content[:60] if msg.reply_to else None,
        "reply_sender":  msg.reply_to.sender.username if msg.reply_to else None,
        "created_at":   msg.created_at.strftime("%H:%M"),
        "sender_name":  msg.sender.display_name,
        "sender_username": msg.sender.username,
    }


# ── Inbox ─────────────────────────────────────────────────

@messages.route("/messages")
@login_required
def inbox():
    me = current_user()

    # Get distinct conversations (latest message per thread)
    seen  = set()
    convos = []
    msgs = Message.query.filter(
        (Message.sender_id == me.id) | (Message.receiver_id == me.id)
    ).order_by(Message.created_at.desc()).all()

    for msg in msgs:
        other_id = msg.receiver_id if msg.sender_id == me.id else msg.sender_id
        if other_id not in seen:
            seen.add(other_id)
            other   = db.session.get(User, other_id)
            unread  = Message.query.filter_by(sender_id=other_id, receiver_id=me.id, is_read=False).count()
            convos.append({"user": other, "last_msg": msg, "unread": unread})

    return render_template("app/messages.html", user=me, convos=convos)


# ── Conversation (full thread) ────────────────────────────

@messages.route("/messages/<int:other_user_id>")
@login_required
def conversation(other_user_id):
    me    = current_user()
    other = db.session.get(User, other_user_id)
    if not other:
        return redirect(url_for("messages.inbox"))

    # Mark as read
    Message.query.filter_by(sender_id=other.id, receiver_id=me.id, is_read=False)\
                 .update({"is_read": True})
    db.session.commit()

    msgs = Message.query.filter(
        ((Message.sender_id == me.id)    & (Message.receiver_id == other.id)) |
        ((Message.sender_id == other.id) & (Message.receiver_id == me.id))
    ).order_by(Message.created_at.asc()).all()

    return render_template("app/conversation.html", user=me, other=other, msgs=msgs)


# ── Real-time send (AJAX) ─────────────────────────────────

@messages.route("/messages/<int:other_user_id>/send", methods=["POST"])
@login_required
def send_message(other_user_id):
    me      = current_user()
    content = request.form.get("content", "").strip()
    reply_to_id = request.form.get("reply_to_id", None, type=int)

    # ❌ VULNERABILITY: sender_id accepted from request body
    # An attacker can send a message appearing to come from any user
    sender_id = request.form.get("sender_id", default=me.id, type=int)

    if not content:
        return jsonify({"status": "error", "message": "Empty message"}), 400

    other = db.session.get(User, other_user_id)
    if not other:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if sender_id != me.id:
        sender = db.session.get(User, sender_id)
        log_exploit(
            vuln_type="IDOR — Send Message as Another User",
            endpoint=f"/messages/{other_user_id}/send",
            description=f"@{me.username} sent a message appearing to be from @{sender.username if sender else sender_id} to @{other.username}",
            severity="critical"
        )

    msg = Message(
        sender_id=sender_id,
        receiver_id=other_user_id,
        content=content,
        reply_to_id=reply_to_id
    )
    db.session.add(msg)
    db.session.commit()

    payload = serialize_msg(msg)

    # Emit to both sender and receiver rooms
    socketio.emit("new_message", payload, room=f"user_{other_user_id}")
    socketio.emit("new_message", payload, room=f"user_{me.id}")

    push_message_notification(me, other_user_id, msg.id)

    return jsonify({"status": "ok", "message": payload})


# ───────────────────────────────────────────
# VULN: IDOR — Read any DM by message ID
# ───────────────────────────────────────────
@messages.route("/messages/view/<int:msg_id>")
@login_required
def view_message(msg_id):
    me  = current_user()
    msg = db.session.get(Message, msg_id)
    if not msg:
        return redirect(url_for("messages.inbox"))

    # ❌ VULNERABILITY: No ownership check
    if msg.sender_id != me.id and msg.receiver_id != me.id:
        log_exploit(
            vuln_type="IDOR — Private Message Access",
            endpoint=f"/messages/view/{msg_id}",
            description=f"@{me.username} read a private DM (ID {msg_id}) between @{msg.sender.username} and @{msg.receiver.username}",
            severity="critical"
        )

    return render_template("app/view_message.html", user=me, msg=msg)


# ───────────────────────────────────────────
# VULN: IDOR — Edit any DM content by ID
# ───────────────────────────────────────────
@messages.route("/messages/edit/<int:msg_id>", methods=["POST"])
@login_required
def edit_message(msg_id):
    me      = current_user()
    msg     = db.session.get(Message, msg_id)
    content = request.form.get("content", "").strip()

    if not msg:
        return jsonify({"status": "error", "message": "Not found"}), 404

    # ❌ VULNERABILITY: No ownership check
    if msg.sender_id != me.id:
        log_exploit(
            vuln_type="IDOR — Private Message Modification",
            endpoint=f"/messages/edit/{msg_id}",
            description=f"@{me.username} edited a DM (ID {msg_id}) sent by @{msg.sender.username}",
            severity="high"
        )

    msg.content = content
    db.session.commit()
    return jsonify({"status": "ok", "content": msg.content})


# ───────────────────────────────────────────
# VULN: IDOR — Delete any DM by message ID
# ───────────────────────────────────────────
@messages.route("/messages/delete/<int:msg_id>", methods=["POST"])
@login_required
def delete_message(msg_id):
    me  = current_user()
    msg = db.session.get(Message, msg_id)
    if not msg:
        return jsonify({"status": "error"}), 404

    if msg.sender_id != me.id and msg.receiver_id != me.id:
        log_exploit(
            vuln_type="IDOR — Private Message Deletion",
            endpoint=f"/messages/delete/{msg_id}",
            description=f"@{me.username} deleted a private DM (ID {msg_id}) between @{msg.sender.username} and @{msg.receiver.username}",
            severity="critical"
        )

    db.session.delete(msg)
    db.session.commit()
    return jsonify({"status": "ok"})