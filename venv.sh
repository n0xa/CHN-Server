#!/bin/sh
# Setup dependencies in a venv
python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt
