"""
routes.py

    Defines all standard static and dynamic routes that can be interfaced by users.
"""
from flask import redirect, render_template, request, flash, current_app, url_for
from flask_login import login_required, current_user

from rq import Queue

from boa import utils, config
from boa.routes import web
from boa.models import Scan
from boa.worker import BoaWorker


# ======================
# Static Content Routes
# ======================


@web.route("/index")
def home_redirect():
    """ Redirects to static home page """
    return redirect(url_for("web.home"))


@web.route("/")
def home():
    """ Renders static home page """
    queries = Scan.query.all()

    # number of executables that have been scanned
    files_scanned: int = len(queries)

    # parse out stats for total number of source files recovered
    source_files_recovered: int = sum([query.src_count for query in queries])

    # total number of security issues found
    security_issues: int = sum([query.issue_count for query in queries])

    return render_template(
        "index.html",
        queries=queries,
        files_scanned=files_scanned,
        source_files_recovered=source_files_recovered,
        security_issues=security_issues,
    )


@web.route("/about")
def about():
    """ Renders informational page """
    return render_template("about.html")


# =======================
# Dynamic Content Routes
# =======================


@web.route("/settings")
@login_required
def settings():
    """ Page that enables users to view and change configurations """
    return render_template("settings.html")


@web.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    """
    Represents endpoint used to conduct a scan against an executable, which does so
    by interacting with the API.
    """
    if request.method == "POST":
        if "file" not in request.files:
            flash("Cannot load file")
            return redirect(request.url)

        # retrieve file information
        input_file = request.files["file"]
        filename = input_file.filename

        # if file somehow ends up being nothing
        if filename == "":
            flash("No file selected!")
            return redirect(request.url)

        # save file to uploads directory/server
        if input_file:

            # retrieve a secure version of the file's name
            # path = werkzeug.utils.secure_filename(filename)

            # instantiate the workspace
            try:
                wker = BoaWorker(
                    filename, current_app.config["UPLOAD_FOLDER"], input_file
                )
            except worker.WorkerException as err:
                flash(str(err))
                return redirect(request.url)

            # enqueue the long-running analysis job
            queue = Queue()
            task = queue.enqueue(wker.identify)

            flash("Successfully uploaded! Starting scan.")
            return redirect(request.url)

        flash("Filetype not allowed!")
        return redirect(request.url)

    # get current user's scans for display
    user_scans = Scan.query.filter_by(user_id=current_user.id)
    return render_template("scan.html", user_scans=user_scans)


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
