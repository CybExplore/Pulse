from flask_socketio import join_room
from extensions import socketio


@socketio.on("join_admin")
def on_join_admin():
    join_room("admin_room")


@socketio.on("join_user")
def on_join_user(data):
    uid = data.get("user_id")
    if uid:
        join_room(f"user_{uid}")


@socketio.on("send_toast")
def on_send_toast(data):
    target_id = data.get("user_id")
    message   = data.get("message", "")
    socketio.emit("toast_notification", {"message": message}, room=f"user_{target_id}")
