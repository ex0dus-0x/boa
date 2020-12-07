"""
__init__.py

    Implements factory method to instantiate Flask application instance
"""

import os
import flask
import sqlalchemy
import sqlalchemy_utils as sqlutils
import flask_socketio as sio

from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy


# initilaize Flask app
app = flask.Flask(__name__, template_folder="templates")
app.secret_key = os.urandom(12)

# instantiate database
db = SQLAlchemy(app)

# instantiate CORS policy for app
cors = CORS(app, resources={r"/socket.io": {"origins": "*"}})

# create Socket.IO interface
socketio = sio.SocketIO(app)


def create_local_dirs(app):
    """ Given a configuration, initialize local workspace paths """

    # create directory to store artifacts and workspaces locally for analysis
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.mkdir(app.config["UPLOAD_FOLDER"])

    # create directory to store database
    if not os.path.exists(app.config["DB_FOLDER"]):
        os.mkdir(app.config["DB_FOLDER"])


def configure_database(app):
    """ Initializes and configure database models """

    @app.before_first_request
    def init_db():
        db_url = app.config["SQLALCHEMY_DATABASE_URI"]
        try:
            engine = sqlalchemy.create_engine(db_url)
            if not sqlutils.database_exists(db_url):
                sqlutils.create_database(db_url)

        except sqlalchemy.exc.OperationalError as err:
            pass

        from boa import models
        models.create_tables(engine)

    @app.teardown_request
    def shutdown(exception=None):
        db.session.remove()


def create_app(config):

    # initialize app from configuration
    app.config.from_object(config)

    create_local_dirs(app)
    configure_database(app)

    from boa import worker
    from boa.models import Scan

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

    # register blueprints
    from boa.web import web

    app.register_blueprint(web)

    db.init_app(app)
    return app
