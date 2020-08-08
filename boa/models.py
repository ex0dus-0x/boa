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

    # basic information
    name = db.Column(db.String(120), unique=False, nullable=False)
    uuid = db.Column(db.String(120), unique=True, nullable=False)

    """
    checksum = db.Column(db.String(120), unique=True, nullable=False)
    timestamp = db.Column(db.String(120), unique=True, nullable=False)

    # python-specific information
    pyver = db.Column(db.Integer, unique=False)
    packer = db.Column(db.String(120))
    total_deps = db.Column(db.Integer)

    # reversing
    pyz_files = db.Column(db.Integer)
    pyc_files = db.Column(db.Integer)
    src_files = db.Column(db.Integer)
    """

    # represents path to local or S3 path for download link to zipped up workspace
    meta_path = db.Column(db.String(240), unique=True, nullable=True)
    zip_url = db.Column(db.String(240), unique=True, nullable=True)

    def __init__(self, name, uuid, timestamp, meta_path, zip_url):
        self.name = name
        self.uuid = uuid
        self.meta_path = meta_path
        self.zip_url = url

    def __repr__(self):
        return "<Name {0}>".format(self.name)


if __name__ == "__main__":
    db.create_all()
