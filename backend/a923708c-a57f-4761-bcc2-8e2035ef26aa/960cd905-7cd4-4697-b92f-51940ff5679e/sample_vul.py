from flask import request
from pathlib import Path
import hashlib
import os

def search(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")

    path = request.args.get("path")
    return Path(path).read_text()

def run_command():
    os.system(request.args["cmd"])

def weak_hash(value):
    return hashlib.md5(value).hexdigest()

api_key = "notarealsecret0123456789abcdefghijklmnop"