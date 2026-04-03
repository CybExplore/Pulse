from werkzeug.security import check_password_hash, generate_password_hash
from flask import Blueprint, render_template, request, redirect, url_for, session
from extensions import db
from models import User

auth = Blueprint("auth", __name__)


@auth.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("feed.home"))
    return render_template("auth/landing.html")


@auth.route("/login", methods=["GET", "POST"])
def login():
    error = None
    from flask import request, redirect, url_for, session
    from werkzeug.security import check_password_hash
    from models import User

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        print("\n=== LOGIN ATTEMPT ===")
        print(f"Username entered : {username}")
        print(f"Password entered : {password}")

        user = User.query.filter_by(username=username).first()

        if not user:
            print("❌ User not found in database")
            error = "Invalid username or password"
        else:
            print(f"User found       : {user.username}")
            print(f"Stored hash      : {user.password}")

            # ✅ ONLY correct way to verify password
            if check_password_hash(user.password, password):
                print("✅ Password is CORRECT → Login successful")

                session.clear()
                session["user_id"]  = user.id
                session["username"] = user.username
                session["role"]     = user.role

                return redirect(url_for("feed.home"))
            else:
                print("❌ Password is INCORRECT")
                error = "Invalid username or password"
        
    return render_template("auth/login.html", error=error)




@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.index"))