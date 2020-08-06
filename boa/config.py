"""
config.py

    Defines constants to be used and configured for the web-based service.
"""

import os

# Flask-specific configurations
TEMPLATES_AUTO_RELOAD = True

# API configurations
API_VERSION = "v1"

# Database configurations
DB_FOLDER = os.path.join(os.getcwd(), "db")
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_DATABASE_URI = "sqlite:///db/boascans.db"

# File upload configurations
UPLOAD_FOLDER = os.path.join(os.getcwd(), "artifacts")
ALLOWED_EXTENSIONS = ["exe", "pe"]
MAX_CONTENT_LENGTH = 1024 ** 3

# Amazon S3 settings - get IAM user key and secret with permission to bucket
AWS_S3_KEY = os.getenv("AWS_S3_KEY")
AWS_S3_SECRET = os.getenv("AWS_S3_SECRET")
AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET")

# this var is unset if no S3 info given, specifically the bucket name
LOCAL_ONLY = True if not AWS_S3_BUCKET else False
