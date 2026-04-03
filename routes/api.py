import jwt as pyjwt
from flask import Blueprint, request, jsonify, current_app
from extensions import db
from models import User
from helpers import current_user, login_required, log_exploit

api = Blueprint("api", __name__)


# ───────────────────────────────────────────
# VULN: JWT — secret leaked, role embedded
# ───────────────────────────────────────────
@api.route("/api/token")
@login_required
def get_token():
    me     = current_user()
    secret = current_app.config["JWT_SECRET"]
    token  = pyjwt.encode(
        {"user_id": me.id, "username": me.username, "role": me.role},
        secret, algorithm="HS256"
    )
    # VULN: secret is intentionally leaked to teach students how to forge tokens
    return jsonify({"token": token, "hint": f"JWT secret is: {secret}"})


# ───────────────────────────────────────────
# VULN: JWT — role claim trusted without DB check
# ───────────────────────────────────────────
@api.route("/api/me")
def api_me():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify({"error": "No token provided"}), 401
    try:
        secret = current_app.config["JWT_SECRET"]
        # ❌ VULNERABILITY: Role taken from token, not re-checked against DB
        data = pyjwt.decode(token, secret, algorithms=["HS256"])
        user = db.session.get(User, data["user_id"])

        if data.get("role") != user.role:
            log_exploit(
                vuln_type="JWT Role Manipulation",
                endpoint="/api/me",
                description=f"'{data['username']}' presented a forged JWT role '{data.get('role')}' (actual: '{user.role}')",
                severity="critical"
            )

        return jsonify({
            "user_id":  data["user_id"],
            "username": data["username"],
            "role":     data["role"],
            "email":    user.email,
            "phone":    user.phone
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401
