"""
auth.py

    Defines all routes that are used specifically for authentication. Used to identify
    scans to a user.
"""

from flask import render_template, request, redirect
from flask_login import login_user, logout_user

from . import web
from ..models import User


@web.route("/login", methods=["GET", "POST"])
def login():
    """ Authenticates a username and password against database """
    if request.method == "POST":

        # get username and hashed password
        username = request.form.get("username")
        pwd = request.form.get("password")

        # check to see if user can be queried
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash("Incorrect credentials")
            return redirect(url_for("web.login"))

        # TODO check password hash

        # login and go back to main page
        login_user(user)
        return redirect(url_for("web.index"))

    return render_template("login.html")


@web.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


@web.route("/signout")
def signout():
    """ Log authenticated user out and redirect to main page """
    logout_user()
    return redirect(url_for("web.index"))


@web.route("/settings")
def settings():
    return redirect(url_for("settings.html"))
