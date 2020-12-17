from flask import Blueprint

web = Blueprint("web", __name__)

from . import routes, auth
