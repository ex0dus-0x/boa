"""
config.py

    Defines constants to be used and configured for the web-based service. The default values of
    these constants are used to help provision a local build, but changes should all be done through
    envvars in their name, preferably set in `.env`.
"""

import os

# Flask-specific configurations
DEBUG_MODE = os.environ.get("DEBUG_MODE", False)
SECRET_KEY = os.urandom(16)
TEMPLATES_AUTO_RELOAD = True
CORS_HEADERS = "Content-Type"

# Database configurations
DB_FOLDER = os.path.join(os.getcwd(), "db")
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI", "sqlite:///{}/boascans.db".format(DB_FOLDER)
)

# File upload configurations
UPLOAD_FOLDER = os.path.join(os.getcwd(), "artifacts")
ALLOWED_EXTENSIONS = ["exe", "pe", "bin"]
MAX_CONTENT_LENGTH = 1024 ** 3

# Amazon S3 settings - get IAM user key and secret with permission to bucket
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
S3_BUCKET = os.environ.get("S3_BUCKET")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
