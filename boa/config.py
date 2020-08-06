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
