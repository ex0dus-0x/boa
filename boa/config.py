"""
config.py

    Defines constants to be used and configured for the web-based service.
"""

import os

# Flask-specific configurations
TEMPLATES_AUTO_RELOAD = True

# API configurations
API_VERSION = "v1"

# File upload configurations
UPLOAD_FOLDER = os.path.join(os.getcwd(), "artifacts")
ALLOWED_EXTENSIONS = ["exe"]
MAX_CONTENT_LENGTH = 1024 ** 3
