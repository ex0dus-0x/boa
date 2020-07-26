"""
models.py

    Database models that are used by Boa for storing persistent information.

"""
import flask_sqlalchemy as fsql


class Scan(db.Model):
    """
    Stores information for a successful boa scan on an executable for
    output consumption as a report. Each entry that is stored doesn't actually
    store all of the information, but acts like a pointer to the workspace
    directory that contains a `metadata.json` configuration.
    """

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), unique=False, nullable=False)

    # represents either a server-side path, or a cloud-based bucket
    workspace = db.Column(db.String(240), unique=True, nullable=True)
