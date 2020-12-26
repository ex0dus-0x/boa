"""
jobs.py

    Defines routes that are used to interact with worker instantiation and
    execution given input samples.

"""
from flask import jsonify, request
from rq import Queue

from boa.routes import web
from boa.worker import BoaWorker


@web.route("/new", methods=["POST"])
def run_job():
    """ Instantiates a new background job conducting a scan """
    return jsonify({"result": "test"})


@web.route("/status/<job_id>")
def job_status(job_id):
    """ Endpoint used to return status for a running job """

    response = {}
    queue = Queue()
    return jsonify(response)


@web.route("/stop/<job_id>")
def stop_job(job_id):
    return
