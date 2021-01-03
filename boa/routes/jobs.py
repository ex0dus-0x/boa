"""
jobs.py

    Defines routes that are used to interact with worker instantiation and
    execution given input samples.
"""
import redis

from flask import jsonify, request, current_app
from rq import Queue, Connection

from boa.routes import web
from boa.worker import BoaWorker


@web.route("/new", methods=["POST"])
def run_job():
    """ Instantiates a new background job conducting a scan """
    with Connection(redis.from_url(current_app.config["REDIS_URL"])):
        q = Queue()
        task = q.enqueue()

    response = {
        "status": "started",
        "data": {
            "id": task.get_id(),
            "status": None,
        }
    }
    return jsonify(response), 202


@web.route("/status/<job_id>", methods=["GET"])
def job_status(job_id):
    """ Endpoint used to return status for a running job """
    with Connection(redis.from_url(current_app.config["REDIS_URL"])):
        q = Queue()
        task = q.fetch_job(task_id)

    # create response based on fetched job
    response = {}
    if task:
        response = {
            "status": "inprogress",
            "data": {
                "id": task.get_id(),
                "status": task.get_status(),
                "result": task.result,
            }
        }
    else:
        response = {"status": "error"}

    return jsonify(response)



@web.route("/stop/<job_id>", methods=["GET"])
def stop_job(job_id):
    """ If pinged, stops a given job ID and destroy artifacts created """
    response = {}
    return jsonify(response)

