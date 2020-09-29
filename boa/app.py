#!/usr/bin/env python3
"""
app.py

    Main web application service for handling all routes and content delivery for the boa service.
    Built in Flask, it contains all the static and dynamic content routes, as well as API endpoints
    that perform a bulk of the reverse engineering functionality.
"""

import os
import flask
import flask_socketio as sio

from flask import redirect, render_template, request, flash
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy

import boa.config as config
import boa.utils as utils

# create directory to store executable artifacts and workspaces locally for analysis
if not os.path.exists(config.UPLOAD_FOLDER):
    os.mkdir(config.UPLOAD_FOLDER)

# create directory to store database
if not os.path.exists(config.DB_FOLDER):
    os.mkdir(config.DB_FOLDER)


# initialize the Flask application with proper configuration
app = flask.Flask(__name__, template_folder="templates")
app.secret_key = os.urandom(12)
app.config.from_object("boa.config")

app.jinja_env.lstrip_blocks = True

# register custom filters to use
app.jinja_env.filters["basename"] = os.path.basename
app.jinja_env.filters["strip"] = str.strip

# instantiate database
db = SQLAlchemy(app)
db.init_app(app)

# .. and then import dependencies that require an instantiated db in order to
# prevent circular dependencies.
from boa import worker
from boa.models import Scan

# .. and finally create any models we need
db.create_all()

# instantiate CORS policy for app
cors = CORS(app, resources={r"/socket.io": {"origins": "*"}})

# initialize Socket.IO interface
socketio = sio.SocketIO(app)

# ======================
# Static Content Routes
# ======================


@app.route("/index")
def home_redirect():
    """ Redirects to static home page """
    return redirect(flask.url_for("home"))


@app.route("/")
def home():
    """ Renders static home page """
    return render_template("index.html")


@app.route("/about")
def about():
    """ Informational route for more technical detail regarding boa """
    return render_template("about.html")


@app.route("/pricing")
def pricing():
    """ Informational route for pricing information regarding boa """
    return render_template("pricing.html")


@app.route("/scan", methods=["GET", "POST"])
@cross_origin(origin="*")
def scan():
    """
    Represents endpoint used to conduct a scan against an executable, which does so
    by interacting with the API.
    """
    if request.method == "POST":
        if "file" not in request.files:
            flash("Cannot load file")
            return flask.redirect(request.url)

        # retrieve file information
        input_file = request.files["file"]
        filename = input_file.filename

        # if file somehow ends up being nothing
        if filename == "":
            flash("No file selected!")
            return flask.redirect(request.url)

        # save file to uploads directory/server
        if input_file:

            # retrieve a secure version of the file's name
            # path = werkzeug.utils.secure_filename(filename)

            # instantiate the workspace, and register namespace with socketio
            try:
                wker = worker.BoaWorker(
                    filename, app.config["UPLOAD_FOLDER"], input_file
                )
            except worker.WorkerException as err:
                flash(str(err))
                return redirect(request.url)

            # register the namespace for socket communication once instantiated
            socketio.on_namespace(wker)

            flash("Successfully uploaded! Starting scan.")
            return redirect(request.url)

        flash("Filetype not allowed!")
        return redirect(request.url)

    queries = Scan.query.all()

    # number of executables that have been scanned
    files_scanned = len(queries)

    # parse out stats for total number of source files recovered
    source_files_recovered = sum([query.src_count for query in queries])

    # total number of security issues found
    security_issues = sum([query.issue_count for query in queries])

    return render_template(
        "scan.html",
        files_scanned=files_scanned,
        source_files_recovered=source_files_recovered,
        security_issues=security_issues,
    )


# =======================
# Dynamic Content Routes
# =======================


@app.route("/report/<uuid>")
def reporter(uuid):
    """
    Dynamically generates a presentable report for consumption by the user
    for the binary parsed out, and returns it JSONified for the frontend.
    """
    # given a uuid, find entry in database, and return dynamic content
    query = Scan.query.filter_by(uuid=uuid).first()
    if query is None:
        return "Not found!"

    # once a query is found, ping the S3 key that is stored for all the metadata information
    report = utils.get_metadata_file(str(query.conf))
    if report is None:
        return "Not found!"

    return render_template("report.html", query=query, report=report)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0")
