"""
__init__.py

    Implements factory method to instantiate Flask application instance
"""

import os
import flask
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
    """ Initializes database model and local storage """

    @app.before_first_request
    def init_db():
        db.create_all()

    @app.teardown_request
    def shutdown(exception=None):
        db.session.remove()


def create_app(config):

    # initialize app from configuration
    app.config.from_object(config)

    # create directories to store  files produced by boa
    create_local_dirs(app)

    db.init_app(app)

    from boa import worker
    from boa.models import Scan

    # Jinja configuration, including filters to pass to templates
    app.jinja_env.lstrip_blocks = True
    app.jinja_env.filters["basename"] = os.path.basename
    app.jinja_env.filters["strip"] = str.strip

    # register blueprints
    from boa.web import web
    app.register_blueprint(web)

    configure_database(app)
    return app
