#!/usr/bin/env python3
"""
WSGI entry point for CHN-Server
"""

import os
import sys

# Add the application directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mhn import create_app

# Create the application instance
application = create_app()
app = application

if __name__ == "__main__":
    application.run()