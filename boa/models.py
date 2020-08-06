"""
models.py

    Database models that are used by Boa for storing persistent information.

"""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    """
    Stores information for a successful boa scan on an executable for
    output consumption as a report. Each entry that is stored doesn't actually
    store all of the information, but acts like a pointer to the workspace
    directory that contains a `metadata.json` configuration.
    """

    __tablename__ = "scan"
    __table_args__ = {"sqlite_autoincrement": True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=False, nullable=False)
    uuid = db.Column(db.String(120), unique=True, nullable=False)

    # represents either a server-side path, or a cloud-based bucket
    workspace = db.Column(db.String(240), unique=True, nullable=True)

    def __init__(self, name, uuid, workspace):
        self.name = name
        self.uuid = uuid
        self.workspace = workspace

    def __repr__(self):
        return "<Name {0}>".format(self.name)
