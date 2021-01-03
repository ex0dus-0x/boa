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
    """ Basic configuration for every boa instance """

    DEBUG = False
    TEMPLATES_AUTO_RELOAD = True
    WTF_CSRF_ENABLED = True

    # Basic settings
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(16))
    CORS_HEADERS = "Content-Type"
    SSL_CONTEXT = "adhoc"

    # Database configurations
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = None

    # Redis configuration default points to local server
    REDIS_URL = "redis://localhost:6379"
    QUEUES = ["default"]

    # File upload configurations for artifacts
    ALLOWED_EXTENSIONS = ["exe", "pe", "bin"]
    MAX_CONTENT_LENGTH = 1024 ** 3
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "artifacts")


class DevelopmentConfig(BaseConfig):
    """ Retains most of BaseConfig configurations, but keeps database local """

    DEBUG = True

    # initializes local path to store database instead of a connection to service
    DB_FOLDER = os.path.join(os.getcwd(), "db")
    SQLALCHEMY_DATABASE_URI = "sqlite:///{}/boa.db".format(DB_FOLDER)


def ProductionConfig(BaseConfig):
    """ Production swaps out local directories for cloud provisioned services  """

    # overrides from BaseConfig
    DEBUG = False
    TEMPLATES_AUTO_RELOAD = False

    # Points to redis instance on another server/container
    REDIS_URL = os.environ.get("REDISTOGO_URL")

    # Points to PostgreSQL database instance on another server/container
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI")

    # Amazon S3 settings - get IAM user key and secret with permission to bucket
    S3_BUCKET = os.environ.get("S3_BUCKET")
    AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
