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
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session["user_id"]  = user.id
            session["username"] = user.username
            session["role"]     = user.role
            return redirect(url_for("feed.home"))
        error = "Invalid username or password"
    return render_template("auth/login.html", error=error)


@auth.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username     = request.form.get("username", "").strip()
        password     = request.form.get("password", "")
        display_name = request.form.get("display_name", username)
        email        = request.form.get("email", "")

        if User.query.filter_by(username=username).first():
            error = "Username already taken"
        else:
            user = User(username=username, password=password,
                        display_name=display_name, email=email)
            db.session.add(user)
            db.session.commit()
            session["user_id"]  = user.id
            session["username"] = user.username
            session["role"]     = user.role
            return redirect(url_for("feed.home"))
    return render_template("auth/register.html", error=error)


@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.index"))