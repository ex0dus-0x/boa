"""
__init__.py

    Define blueprints needed and redis task queue.
"""
import rq
import redis
from flask import Blueprint, current_app, g

def get_redis_connection():
    """ Helper used to pass connection when instantiating a Queue """
    redis_connection = getattr(g, "_redis_connection", None)
    if redis_connection is None:
        redis_url = current_app.config["REDIS_URL"]
        redis_connection = g._redis_connection = redis.from_url(redis_url)
    return redis_connection


# define routes that serves all static and dynamic content
web = Blueprint("web", __name__)

@web.before_request
def push_rq_conn():
    rq.push_connection(conn=get_redis_connection())

@web.teardown_request
def pop_rq_conn(exception=None):
    rq.pop_connection()

# now import all decorated callbacks
from . import routes, auth, jobs
