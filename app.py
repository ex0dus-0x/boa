#!/usr/bin/env python3
"""
app.py
"""
import os
import json
import flask

import boa.config
import boa.utils

app = flask.Flask(__name__, template_folder="templates")
app.config.from_object("boa.config")


#==============================
# Basic static content routes:
#
#   / and /index
#   /about
#   /scan
#
#==============================

@app.route("/index")
def home_redirect():
    return flask.redirect_url("home")


@app.route("/")
def home():
    return flask.render_template("index.html")


@app.route("/about")
def about():
    return flask.render_template("about.html")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    return flask.render_template("scan.html")


#======================================
# Reverse Engineering API Functionality
#
#   /api/VERSION
#   /api/VERSION/stats
#   /api/VERSION/scan
#
#=====================================

pyre = flask.Blueprint("api", __name__)

@app.route(utils.endpoint("scan"), methods=["POST"])
def api_scan():
    pass

@app.route(utils.endpoint("stats"))
def api_stats():
    pass


if __name__ == "__main__":
    app.run(use_reloader=True, host="0.0.0.0")
