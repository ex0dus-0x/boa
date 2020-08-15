"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    ap.config.from_object("boa.config.Config")

    db.init_app(app)

    with app.app_context():
        from boa import routes
        db.create_all()
        return app
"""
