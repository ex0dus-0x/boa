"""
auth.py

    Defines all routes that are used specifically for authentication. Used to identify
    scans to a user.
"""
import hashlib

from flask import render_template, request, redirect, flash, url_for
from flask_login import login_user, logout_user

from . import web
from .. import db
from ..models import User
from ..forms import RegistrationForm, LoginForm


def password_hasher(cleartext):
    """ Generates a SHA-256 hash of a given cleartext """
    hasher = hashlib.sha256()
    hasher.update(cleartext)
    return hasher.hexdigest()


@web.route("/login", methods=["GET", "POST"])
def login():
    """ Authenticates a username and password against database """
    form = LoginForm(request.form)
    if request.method == "POST":

        # check if form meets validation standards
        if not form.validate():
            flash("Cannot validate authentication data.")
            return redirect(url_for("web.login"))

        # get username and hashed password
        username = form.username.data
        password = password_hasher(form.password.data.encode())

        # check to see if user can be queried
        user = User.query.filter_by(username=username, password=password).first()
        if user is None:
            flash("Incorrect credentials.")
            return redirect(url_for("web.login"))

        # TODO check password hash

        # login and go back to main page
        login_user(user)
        return redirect(url_for("web.home"))

    return render_template("login.html", form=form)


@web.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm(request.form)
    if request.method == "POST":

        # check if form data is valid
        if not form.validate():
            flash("Password: ".join(form.errors["password"]))
            return redirect(url_for("web.register"))

        username = form.username.data
        email = form.email.data
        password = password_hasher(form.password.data.encode())

        # check if user already exists
        user = User.query.filter_by(username=username, email=email).first()
        if user:
            flash("Username/email already exists.")
            return redirect(url_for("web.register"))

        # TODO generate API token
        api_key = b"testingkey"
        new_user = User(email, username, password, api_key)

        # add and commit to user database
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception:
            flash("Cannot register user to platform. Contact admin.")
            return redirect(url_for("web.register"))

        # successful!
        flash("Successfully created account! You can now login.")
        return redirect(url_for("web.login"))

    return render_template("register.html", form=form)


@web.route("/signout")
def signout():
    """ Log authenticated user out and redirect to main page """
    logout_user()
    flash("Successfully logged out of account!")
    return redirect(url_for("web.login"))


@web.route("/settings")
def settings():
    return redirect(url_for("settings.html"))
