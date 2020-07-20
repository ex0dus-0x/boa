#!/usr/bin/env python3
"""
manager.py

    Main web application service for handling all routes and content delivery for the boa service.
    Built in Flask, it contains all the static and dynamic content routes, as well as API endpoints
    that perform a bulk of the reverse engineering functionality.

"""
import os
import shutil
import json
import flask
import flask_socketio as sio
import werkzeug

import boa.config as config
import boa.utils as utils

from flask import redirect, render_template, request, flash

from boa.core import worker, unpack

# initialize the Flask application with proper configuration
app = flask.Flask(__name__, template_folder="templates")
app.secret_key = os.urandom(12)
app.config.from_object("boa.config")

# initialize Socket.IO interface
socketio = sio.SocketIO(app)

# create directory to store executable artifacts and workspaces
# TODO: option to disable if configured to use S3
if not os.path.exists(config.UPLOAD_FOLDER):
     os.mkdir(config.UPLOAD_FOLDER)

#======================
# Static Content Routes
#======================

@app.route("/index")
def home_redirect():
    return redirect(flask.url_for("home"))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    """ Informational route for more technical detail regarding boa """
    return render_template("about.html")


@app.route("/scan", methods=["GET", "POST"])
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
        # TODO: remove `not` once set
        if input_file and not utils.allowed_file(filename):

            # TODO: check against database to see if sample exists, and
            # redirect to report if found

            # retrieve a secure version of the file's name
            path = werkzeug.utils.secure_filename(filename)

            # TODO: rudimentary malware check with Virustotal

            # instantiate the workspace, and register namespace with socketio
            try:
                w = worker.BoaWorker(filename, app.config["UPLOAD_FOLDER"], input_file)
            except worker.WorkerException as e:
                flash(str(e))
                return redirect(request.url)

            # register the namespace for socket communication once instantiated
            socketio.on_namespace(w)

            flash("Successfully uploaded! Starting scan.")
            return redirect(request.url)

        flash("Filetype not allowed!")
        return redirect(request.url)

    files_scanned = 0
    source_files_recovered = 0
    return render_template("scan.html",
            files_scanned=files_scanned,
            source_files_recovered=source_files_recovered)


#=======================
# Dynamic Content Routes
#=======================

@app.route("/report/<uuid>")
def report(uuid):
    """
    Dynamically generates a presentable report for consumption by the user for the binary parsed out.
    """
    # TODO: given a uuid, find entry in database, and return dynamic content
    return render_template("report.html")


#==================
# API Functionality
#==================

pyre = flask.Blueprint("api", __name__)

@app.route(utils.endpoint("stats"))
def api_stats():
    """
    Informational API endpoint that displays stats about the boa service.
    """
    pass


@app.route(utils.endpoint("scan"), methods=["POST"])
def api_scan():
    """
    Main endpoint used to consume a file upload through a POST request.
    """
    pass

if __name__ == "__main__":
    socketio.run(app, use_reloader=True, host="0.0.0.0")
