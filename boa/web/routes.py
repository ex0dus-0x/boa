#!/usr/bin/env python3
"""
routes.py
"""

import flask

from flask import redirect, render_template, request, flash, current_app
from flask_cors import cross_origin

import boa.utils as utils
import boa.config as config

from . import web
from boa import worker, socketio
from boa.models import Scan


# ======================
# Static Content Routes
# ======================


@web.route("/index")
def home_redirect():
    """ Redirects to static home page """
    return redirect(flask.url_for("web.home"))


@web.route("/")
def home():
    """ Renders static home page """
    return render_template("index.html")


@web.route("/about")
def about():
    """ Informational route for more technical detail regarding boa """
    return render_template("about.html")


@web.route("/pricing")
def pricing():
    """ Informational route for pricing information regarding boa """
    return render_template("pricing.html")


@web.route("/scan", methods=["GET", "POST"])
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
                    filename, current_app.config["UPLOAD_FOLDER"], input_file
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


@web.route("/report/<uuid>")
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