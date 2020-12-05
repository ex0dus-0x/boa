"""
models.py

    Database models that are used by Boa for storing persistent information.

"""
from sqlalchemy.ext.declarative import declarative_base

from boa.app import db


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

    # TODO: make unique once we incorporate checking checksums
    checksum = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.String(120), unique=True, nullable=False)

    # represents path to local or S3 path for download link to zipped up workspace
    conf = db.Column(db.String(240), nullable=True)
    zipurl = db.Column(db.String(240), unique=True, nullable=True)

    # metadata for stats
    src_count = db.Column(db.Integer)
    issue_count = db.Column(db.Integer)

    def __init__(self, name, uuid, checksum, timestamp, conf, zipurl):
        self.name = name
        self.uuid = uuid
        self.checksum = checksum
        self.timestamp = timestamp
        self.conf = conf
        self.zipurl = zipurl

    def with_stats(self, src, issue):
        """
        Instantiates stats that can be queried for the scan page.
        """
        self.src_count = src
        self.issue_count = issue

    def __repr__(self):
        return "<Scan {0}>".format(self.name)
