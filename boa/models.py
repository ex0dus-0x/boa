"""
models.py

    Database models that are used by Boa for storing persistent information.

"""
from sqlalchemy.ext.declarative import declarative_base

from . import db

# initialize declarative base to inherit for database models
Base = declarative_base()


def create_tables(engine):
    """ Initialize database with structure """
    Base.metadata.create_all(engine)


class User(db.Model):
    """ TODO """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=True, nullable=False)



class Scan(Base, db.Model):
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

    checksum = db.Column(db.String(120), unique=True, nullable=False)
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
