"""
config.py

    Defines constants to be used and configured for the web-based service. The default values of
    these constants are used to help provision a local build, but changes should all be done through
    envvars in their name, preferably set in `.env`.
"""

import os

# Flask-specific configurations
TEMPLATES_AUTO_RELOAD = True
CORS_HEADERS = "Content-Type"

# API configurations
API_VERSION = "v1"

# Database configurations
DB_FOLDER = os.path.join(os.getcwd(), "db")
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI", "sqlite:///{}/boascans.db".format(DB_FOLDER))

# File upload configurations
UPLOAD_FOLDER = os.path.join(os.getcwd(), "artifacts")
ALLOWED_EXTENSIONS = ["exe", "pe"]
MAX_CONTENT_LENGTH = 1024 ** 3

# Amazon S3 settings - get IAM user key and secret with permission to bucket
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
S3_BUCKET = os.environ.get("S3_BUCKET")

# this var is unset if no S3 info given, specifically the bucket name
LOCAL_ONLY = True if not S3_BUCKET else False
