# Paste this into your PythonAnywhere WSGI configuration file
# (Web tab -> "WSGI configuration file" link), replacing everything in it.
# Change YOUR_USERNAME to your PythonAnywhere username.

import os
import sys

path = "/home/YOUR_USERNAME/ctf"
if path not in sys.path:
    sys.path.insert(0, path)

# Change this to any long random text.
os.environ["SECRET_KEY"] = "put-a-long-random-string-here"

from app import app as application  # noqa: E402
