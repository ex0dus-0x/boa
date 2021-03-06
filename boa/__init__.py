"""
__init__.py

    Implements factory method to instantiate Flask application instance
"""

import os
import flask
import sqlalchemy
import sqlalchemy_utils as sqlutils

from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

from boa.utils import UploadClient

db = SQLAlchemy()

# initilaize Flask app
app = flask.Flask(__name__, template_folder="templates")
app.secret_key = os.urandom(12)


def create_local_dirs(app):
    """ Given a configuration, initialize local workspace paths """

    # create directory to store artifacts and workspaces locally for analysis
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.mkdir(app.config["UPLOAD_FOLDER"])

    # if specified, create directory to store database
    if "DB_FOLDER" in app.config:
        if not os.path.exists(app.config["DB_FOLDER"]):
            os.mkdir(app.config["DB_FOLDER"])


def configure_database(app):
    """ Initializes and configure database models """

    @app.before_request
    def startup():
        db_url = app.config["SQLALCHEMY_DATABASE_URI"]
        try:
            engine = sqlalchemy.create_engine(db_url)
            if not sqlutils.database_exists(db_url):
                sqlutils.create_database(db_url)

            from boa import models

            models.create_tables(engine)

        except sqlalchemy.exc.OperationalError as err:
            print("Failed to connect to database. Reason: ", err)
            exit(1)

    @app.teardown_request
    def shutdown(exception=None):
        db.session.remove()


def create_app(config):
    """ Main factory method that consumes a configuration and instantiates state for boa """

    # initialize app from configuration
    app.config.from_object(config)

    # instantiate a S3 bucket helper object if production build
    try:
        if not app.config["DEBUG"]:
            app.config["BUCKET_HELPER"] = UploadClient(app.config)
    except KeyError:
        print("Cannot run in production without S3 bucket and credential envvars set.")
        exit(1)

    # create local workspace and configure database
    create_local_dirs(app)
    configure_database(app)

    # configure authentication
    login_manager = LoginManager()
    login_manager.login_view = "web.login"
    login_manager.init_app(app)

    from boa import worker
    from boa.models import Scan, User

    @login_manager.user_loader
    def load_user(user):
        return User.query.get(int(user))

    # Jinja configuration, including filters to pass to templates
    app.jinja_env.lstrip_blocks = True
    app.jinja_env.filters["basename"] = os.path.basename
    app.jinja_env.filters["strip"] = str.strip

    @app.errorhandler(404)
    def page_not_found(error):
        """ Redirect to custom 404 page """
        return flask.render_template("404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(Error):
        """ Redirect to home if request method not allowed """
        return flask.redirect(flask.url_for("web.index"))

    # register server-sent event blueprint
    from flask_sse import sse

    app.register_blueprint(sse, url_prefix="/stream")

    # register blueprints
    from boa.routes import web

    app.register_blueprint(web)

    db.init_app(app)
    return app
