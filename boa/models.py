"""
models.py

    Database models that are used by Boa for storing persistent information.
"""

from flask_login import UserMixin
from sqlalchemy.ext.declarative import declarative_base

from . import db

# initialize declarative base to inherit for database models
Base = declarative_base()


def create_tables(engine):
    """ Initialize database with structure """
    Base.metadata.create_all(engine)


class User(Base, UserMixin, db.Model):
    """ Represents a model for an authenticated user """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=True, nullable=False)
    api_key = db.Column(db.String(255), unique=True, nullable=False)

    def __init__(self, email, username, password, api_key):
        self.email = email
        self.username = username
        self.password = password
        self.api_key = api_key


class Scan(Base, db.Model):
    """ Stores scan results for a given target executable """

    __tablename__ = "scans"
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

    # relationship with User
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", backref="scans")

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

    @classmethod
    def get_scans_by_user(cls, username):
        """ TODO: get scans by username relationship """
        pass

    def __repr__(self):
        return "<Scan {0}>".format(self.name)
