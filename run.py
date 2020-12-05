#!/usr/bin/env python3
"""
run.py

"""
from boa import create_app
from config import BaseConfig

# initialize Flask app with factory pattern
config = BaseConfig()
app = create_app(config)

if __name__ == "__main__":
    app.run()
