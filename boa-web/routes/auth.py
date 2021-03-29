"""
auth.py

    Defines all routes that are used specifically for authentication. Used to identify
    scans to a user.
"""
import os
import binascii
import hashlib

from flask import render_template, request, redirect, flash, url_for
from flask_login import login_user, logout_user

from boa import db
from boa.routes import web
from boa.models import User
from boa.forms import RegistrationForm, LoginForm


def password_hasher(username, pwd):
    """ Generates a unique SHA-256 hash of a given auth combo  """
    hasher = hashlib.sha256()
    hasher.update(username)
    hasher.update(pwd)
    return hasher.hexdigest()


def generate_api_key():
    """ Generates a pseudorandom API key for a given registered account """
    return binascii.b2a_hex(os.urandom(16))


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
        password = password_hasher(username.encode(), form.password.data.encode())

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
        password = password_hasher(username.encode(), form.password.data.encode())

        # check if user already exists
        user = User.query.filter_by(username=username, email=email).first()
        if user:
            flash("Username/email already exists.")
            return redirect(url_for("web.register"))

        # generate API token
        api_key = generate_api_key()

        # add and commit to user database
        new_user = User(email, username, password, api_key)
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
