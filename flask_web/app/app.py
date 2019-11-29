from flask import Flask
from flask import request
from flask import make_response
from flask import render_template
import requests
import json
import redis
import rusers
import rsessions
import tokens
from dotenv import load_dotenv
from os import getenv
import sys

app = Flask(__name__)

load_dotenv(verbose=True)
PDF = getenv("PDF_HOST")
WEB = getenv("WEB_HOST")
SESSION_TIME = int(getenv("SESSION_TIME"))
JWT_SESSION_TIME = int(getenv('JWT_SESSION_TIME'))
JWT_SECRET = getenv("JWT_SECRET")
INVALIDATE = -1

cache = redis.Redis(host='web_db', port=6379, db=0)
usrs_manager = rusers.UsersManager(cache)
usrs_manager.init_redis_with_users()
sessions_manager = rsessions.SessionsManager(cache)
tokens_manager = tokens.TokenManager(
    SESSION_TIME, JWT_SESSION_TIME, JWT_SECRET)


@app.route('/')
def index():
    session_id = request.cookies.get('session_id')
    if sessions_manager.validate_session(session_id):
        return redirect("/welcome")
    else:
        return redirect("/login")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/auth', methods=['POST'])
def auth():
    username = request.form.get('username')
    password = request.form.get('password')

    response = make_response('', 303)

    #print(password, file=sys.stderr)
    if usrs_manager.validate_credentials(username, password):
        session_id = sessions_manager.create_session(username)
        response.set_cookie("session_id", session_id, max_age=SESSION_TIME)
        response.headers["Location"] = "/welcome"
    else:
        response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
        response.headers["Location"] = "/login"

    return response


@app.route('/welcome')
def welcome():
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)
    if sessions_manager.validate_session(session_id) and username is not None:
        upload_token = tokens_manager.create_upload_token(
            username.decode()).decode('ascii')
        list_token = tokens_manager.create_getFileList_token(
            username.decode()).decode('ascii')

        req = requests.get("http://pdf:5000/files/" +
                           username.decode() + "?token=" + list_token)
        if req.status_code == 200:
            file_list = req.json()
        else:
            file_list = []

        return render_template("welcome.html", file_list=file_list, PDF=PDF, upload_token=upload_token, WEB=WEB)
    return redirect("/login")


@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id is not None:
        sessions_manager.delete_session(session_id)

    response = redirect("/login")
    response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
    return response


@app.route('/callback')
def uploaded():
    session_id = request.cookies.get('session_id')
    if not session_id or not sessions_manager.validate_session(session_id):
        return redirect("/login")

    fname = request.args.get('filename')
    fid = request.args.get('fid')
    err = request.args.get('error')

    if err:
        return f"<h1>APP</h1> Upload failed: {err}", 400
    if not fid or not fname:
        return f"<h1>APP</h1> Upload successfull, but no fid/file name returned", 500
    content_type = request.args.get('content_type', 'text/plain')
    username = sessions_manager.get_session_user(session_id).decode()
    return f"<h1>APP</h1> User {username} uploaded {fname} - {fid} ({content_type})", 200


def redirect(location):
    response = make_response('', 303)
    response.headers["Location"] = location
    return response
