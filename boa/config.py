"""
config.py

    Defines constants to be used and configured for the web-based service. The default values of
    these constants are used to help provision a local build, but changes should all be done through
    envvars in their name, preferably set in `.env`.
"""

import os
import dotenv

dotenv.load_dotenv()


class BaseConfig(object):
    """Defines globally set variables and configurations, and should also be used
    as the default development configuration"""

    SECRET_KEY = os.urandom(16)
    CORS_HEADERS = "Content-Type"
    SSL_CONTEXT = "adhoc"
    TEMPLATES_AUTO_RELOAD = True

    # Database configurations
    DB_FOLDER = os.path.join(os.getcwd(), "db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///{}/boa.db".format(DB_FOLDER)

    # File upload configurations
    ALLOWED_EXTENSIONS = ["exe", "pe", "bin"]
    MAX_CONTENT_LENGTH = 1024 ** 3
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "artifacts")


def ProductionConfig(BaseConfig):
    """ Production swaps out local directories for cloud provisioned services  """

    TEMPLATES_AUTO_RELOAD = False

    # Points to relational database instance
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")

    # Amazon S3 settings - get IAM user key and secret with permission to bucket
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    S3_BUCKET = os.environ.get("S3_BUCKET")
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
