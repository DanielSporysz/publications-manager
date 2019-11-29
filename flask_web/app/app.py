from flask import Flask
from flask import request
from flask import make_response
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
HTML = """<!doctype html>
<head><meta charset="utf-8"/></head>"""

cache = redis.Redis(host='web_db', port=6379, db=0)
usrs_manager = rusers.UsersManager(cache)
usrs_manager.init_redis_with_users()
sessions_manager = rsessions.SessionsManager(cache)
tokens_creator = tokens.TokenCreator(
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
    return f"""{HTML}
  <h1>APP</h1>
  <form action="/auth" method="POST">
    <input type="text"     name="username" placeholder="Username"></input>
    <input type="password" name="password" placeholder="Password"></input>
    <input type="submit"/>
  </form>"""


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
    if sessions_manager.validate_session(session_id):
        upload_token = tokens_creator.create_upload_token().decode('ascii')
        return f"""{HTML}
    <h1>APP</h1>
    <form action="{PDF}/upload" method="POST" enctype="multipart/form-data">
      <input type="file" name="file"/>
      <input type="hidden" name="token"    value="{upload_token}" />
      <input type="hidden" name="callback" value="{WEB}/callback" />
      <input type="submit"/>
    </form> """
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
    fid = request.args.get('fid')
    err = request.args.get('error')
    if not session_id:
        return redirect("/login")

    if err:
        return f"<h1>APP</h1> Upload failed: {err}", 400
    if not fid:
        return f"<h1>APP</h1> Upload successfull, but no fid returned", 500
    content_type = request.args.get('content_type', 'text/plain')
    return f"<h1>APP</h1> User {session_id} uploaded {fid} ({content_type})", 200


def redirect(location):
    response = make_response('', 303)
    response.headers["Location"] = location
    return response
