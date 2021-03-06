"""
jobs.py

    Defines routes that are used to interact with worker instantiation and
    execution given input samples.
"""
import rq
import redis

from flask import jsonify, request, current_app, g
from rq import Queue

from boa.routes import web
from boa.worker import BoaWorker


def get_redis_connection():
    """ Get attribute to redis connecion object """
    conn = getattr(g, "_redis_connection", None)
    if conn is None:
        url = current_app.config["REDIS_URL"]
        conn = g._redis_connection = redis.from_url(url)
    return conn


@web.before_request
def push_rq_connection():
    rq.push_connection(get_redis_connection())


@web.teardown_request
def pop_rq_connection(execption=None):
    rq.pop_connection()


#########################################
# Endpoints for starting background jobs
#########################################


@web.route("/status/<job_id>", methods=["GET"])
def job_status(job_id):
    """ Endpoint used to return status for a running job """
    queue = Queue()
    task = queue.fetch_job(job_id)

    # define response based on task
    response = {}
    if task is None:
        response = {"status": "unknown"}
    else:
        response = {
            "status": "inprogress",
            "data": {
                "id": task.get_id(),
                "status": task.get_status(),
                "result": task.result,
            },
        }
    return jsonify(response)

# TODO: stop job
