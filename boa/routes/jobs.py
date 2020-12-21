"""
jobs.py

    Defines routes that are used to interact with worker instantiation and
    execution given input samples.

"""
from flask import jsonify, request
from rq import Queue

from boa.routes import web
from boa.worker import Worker


@web.route("/new_job", methods=["POST"])
def run_task():
    """ """

    return jsonify({"result" : "test"})


@web.route("/status/<job_id>")
def job_status(job_id):
    """ """

    response = {}
    queue = Queue()
    return jsonify(response)
