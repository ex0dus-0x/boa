from flask import Blueprint

# define routes that serves all static and dynamic content
web = Blueprint("web", __name__)

# now import all decorated callbacks
from . import routes, auth
